#!/usr/bin/env python3
"""netstats -- the SekurIRCd network stats panel. Python 3.11+, standard library only.

bin/services collects (services/stats.c, on when stats.toml has [collector] enabled = true) and appends to
stats/events.log; this loads that into a SQLite database (rollups + retention), checks every server from outside
(ports, TLS certificate), places servers on a world map (offline GeoIP or stats.toml), and shows it all as one HTML
page: served live with admin/viewer logins, or written to files for a website (cron).

  netstats.py serve [--daemon] [--pidfile P]   the web panel (loads the log every minute, probes every 5)
  netstats.py --stop [--pidfile P]             stop a --daemon
  netstats.py render                           load the log, write the [export] html files (for cron)
  netstats.py ingest                           just load the log into the database
  netstats.py --user --admin|--viewer --add NAME   add a login to stats.toml (asks for the password)
  netstats.py --user --admin|--viewer --del NAME   remove it
  netstats.py --user [--admin|--viewer] --status   list the logins
  netstats.py --mkpasswd                       print a password hash, for a [[users]] entry written by hand
  netstats.py geoip-update                     download the free DB-IP Lite city database (CC BY 4.0)
  netstats.py check                            validate stats.toml (exit 3: valid, but no login can open the panel)
  netstats.py selftest                         offline self-check (synthetic log -> database -> page)
Every command takes -c/--config (default: stats.toml next to this file)."""
import argparse, base64, fcntl, getpass, gzip, hashlib, hmac, html, http.server, ipaddress, json, os, re, secrets, signal
import socket, socketserver, sqlite3, ssl, sys, tempfile, threading, time, urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone

try:
    import tomllib
except ImportError:  # pragma: no cover
    sys.exit("netstats needs Python 3.11 or newer (tomllib)")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ASSETS = os.path.join(HERE, "assets")
DAY, HOUR = 86400, 3600
SESSION_TTL = 12 * HOUR  # a browser stays logged in this long, or until it logs out

# The login form (the panel's only other page). /*...*/ placeholders: network name, error line, link back to the public page.
LOGIN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Log in</title>
<script>try{var t=localStorage.getItem('netstats-theme');if(t)document.documentElement.dataset.theme=t}catch(e){}</script>
<style>
:root{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--surface-2:#f3f2ee;--ink:#0b0b0b;--ink-2:#52514e;--muted:#898781;--axis:#c3c2b7;--ring:rgba(11,11,11,.10);--accent:#2a78d6;--crit:#d03b3b}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--surface-2:#232321;--ink:#f0efec;--ink-2:#c3c2b7;--axis:#383835;--ring:rgba(255,255,255,.10);--accent:#3987e5}}
:root[data-theme="dark"]{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--surface-2:#232321;--ink:#f0efec;--ink-2:#c3c2b7;--axis:#383835;--ring:rgba(255,255,255,.10);--accent:#3987e5}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:var(--page);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
form{width:100%;max-width:340px;background:var(--surface);border-radius:12px;box-shadow:0 0 0 1px var(--ring);padding:24px}
h1{font-size:16px;margin:0 0 16px;font-weight:650}
label{display:block;font-size:12px;color:var(--ink-2);margin:0 0 12px}
input{display:block;width:100%;margin-top:4px;font:inherit;font-size:14px;padding:8px 10px;border-radius:8px;border:0;background:var(--surface-2);color:var(--ink);box-shadow:inset 0 0 0 1px var(--ring)}
input:focus-visible{outline:2px solid var(--accent)}
button{width:100%;font:inherit;font-weight:600;padding:9px;border:0;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer}
button:focus-visible{outline:2px solid var(--ink)}
.err{color:var(--crit);font-size:13px;margin:0 0 12px}
p{margin:14px 0 0;text-align:center;font-size:12px}
a{color:var(--accent)}
</style></head><body>
<form method="post" action="/login">
<h1>/*NET*/ network stats</h1>
/*ERR*/<label>Name<input name="user" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="40" required autofocus></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required></label>
<button>Log in</button>
/*BACK*/</form>
</body></html>
"""
RAW_DAYS, HOURLY_DAYS, STATLINE_DAYS = 7, 90, 35
ROLES = ("admin", "viewer")


# --- config ----------------------------------------------------------------------------------------------------------

class ConfigError(Exception):
    pass


def load_config(path):
    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except FileNotFoundError:
        raise ConfigError(f"{path} not found -- copy stats/stats.template.toml to it")
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"invalid TOML in {path}: {e}")
    base = os.path.dirname(os.path.abspath(path))
    rel = lambda p: p if not p or os.path.isabs(p) else os.path.join(base, p)
    col, sto, web, exp, geo, hea = (raw.get(k, {}) for k in ("collector", "storage", "http", "export", "geoip", "health"))
    c = {
        "path": os.path.abspath(path),
        "network": str(web.get("network_name", "") or "IRC network"),
        "sample": int(col.get("sample_seconds", 60)),
        "log": rel(col.get("log", "events.log")),
        "db": rel(sto.get("database", "stats.db")),
        "retention": int(sto.get("retention_days", 365)),
        "http": {"enabled": bool(web.get("enabled", True)), "bind": str(web.get("bind", "127.0.0.1")),
                 "port": int(web.get("port", 8089)), "tls_cert": rel(web.get("tls_cert", "")),
                 "tls_key": rel(web.get("tls_key", "")), "public": bool(web.get("public", False)),
                 "hostname": str(web.get("hostname", "")).strip().lower().rstrip("."),
                 "trusted_proxies": [str(x) for x in web.get("trusted_proxies",
                                                              ["127.0.0.1", "::1"] if web.get("hostname") else [])]},
        "export": {"public_html": rel(exp.get("public_html", "")), "admin_html": rel(exp.get("admin_html", ""))},
        "geoip": rel(geo.get("file", "dbip-city-lite.csv.gz")),
        "health": {"ports": [int(p) for p in hea.get("ports", [6667, 6697])],
                   "tls_ports": [int(p) for p in hea.get("tls_ports", [6697])],
                   "interval": int(hea.get("interval", 300)), "timeout": float(hea.get("timeout", 5))},
        "users": [], "servers": {},
    }
    if not 7 <= c["retention"] <= 3650:
        raise ConfigError("[storage] retention_days must be 7..3650")
    if not 1 <= c["http"]["port"] <= 65535:
        raise ConfigError("[http] port must be 1..65535")
    host = c["http"]["hostname"]
    if host and not re.fullmatch(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}", host):
        raise ConfigError(f"[http] hostname {host!r} is not a host name like stats.example.net")
    for x in c["http"]["trusted_proxies"]:
        try:
            ipaddress.ip_address(x)
        except ValueError:
            raise ConfigError(f"[http] trusted_proxies: {x!r} is not an IP address")
    if bool(c["http"]["tls_cert"]) != bool(c["http"]["tls_key"]):
        raise ConfigError("[http] tls_cert and tls_key go together")
    for u in raw.get("users", []):
        if not u.get("name") or not str(u.get("password", "")).startswith("scrypt$"):
            raise ConfigError("every [[users]] needs a name and a password made by 'netstats.py hash'")
        if u.get("role", "viewer") not in ROLES:
            raise ConfigError(f"[[users]] {u['name']}: role must be admin or viewer")
        c["users"].append({"name": str(u["name"]), "password": str(u["password"]), "role": u.get("role", "viewer")})
    for s in raw.get("servers", []):
        if not s.get("name"):
            raise ConfigError("every [[servers]] needs the server's name")
        if ("lat" in s) != ("lon" in s):
            raise ConfigError(f"[[servers]] {s['name']}: lat and lon go together")
        c["servers"][s["name"].lower()] = s
    return c


# --- passwords (same scrypt format as the ircd's oper passwords, tools/linkmgmt.py scrypt_hash) ------------------------

def hash_password(pw):
    salt = secrets.token_bytes(16)
    d = hashlib.scrypt(pw.encode(), salt=salt, n=16384, r=8, p=1, dklen=64, maxmem=32 * 1024 * 1024)
    return f"scrypt$16384$8$1${salt.hex()}${d.hex()}"


def check_password(pw, stored):
    try:
        _, n, r, p, salt, want = stored.split("$")
        d = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=len(want) // 2,
                           maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(d.hex(), want)
    except (ValueError, TypeError):
        return False


# --- database --------------------------------------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS net(t INTEGER PRIMARY KEY, users INT, channels INT, regchans INT, opers INT, away INT, tls INT,
                               logged INT, peak INT, accounts INT, regchans_cs INT);
CREATE TABLE IF NOT EXISTS srv(t INT, name TEXT, users INT, PRIMARY KEY(t, name));
CREATE TABLE IF NOT EXISTS net_h(t INTEGER PRIMARY KEY, umin INT, uavg REAL, umax INT, accounts INT, channels INT);
CREATE TABLE IF NOT EXISTS net_d(t INTEGER PRIMARY KEY, umin INT, uavg REAL, umax INT, accounts INT, channels INT);
CREATE TABLE IF NOT EXISTS servers(name TEXT PRIMARY KEY, sid TEXT, uplink TEXT, hop INT, descr TEXT, first_seen INT,
                                   last_seen INT, linked_at INT, present INT, users INT);
CREATE TABLE IF NOT EXISTS outages(id INTEGER PRIMARY KEY, name TEXT, uplink TEXT, start INT, end INT, reason TEXT);
CREATE INDEX IF NOT EXISTS outages_name ON outages(name, start);
CREATE TABLE IF NOT EXISTS svc(t INT, ev TEXT, version TEXT);
CREATE TABLE IF NOT EXISTS bans(t INT, type TEXT, by TEXT, dur INT, mask TEXT, reason TEXT);
CREATE INDEX IF NOT EXISTS bans_t ON bans(t);
CREATE TABLE IF NOT EXISTS statline(t INT, name TEXT, cpu REAL, mem INT, conns INT, dnsbl INT, kl INT, gl INT, zl INT,
                                    local INT, version TEXT, dnsbl_bans INT, scan_bans INT, scanned INT, proxies INT,
                                    spam INT, spam_rules INT, PRIMARY KEY(t, name));
CREATE TABLE IF NOT EXISTS probes(name TEXT, port INT, t INT, ok INT, ms REAL, err TEXT, tls INT, cert_days INT,
                                  PRIMARY KEY(name, port));
CREATE TABLE IF NOT EXISTS geo(host TEXT PRIMARY KEY, ip TEXT, city TEXT, country TEXT, lat REAL, lon REAL, t INT);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""


def open_db(c):
    os.makedirs(os.path.dirname(c["db"]) or ".", exist_ok=True)
    db = sqlite3.connect(c["db"], timeout=30)
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA)
    have = {r[1] for r in db.execute("PRAGMA table_info(statline)")}
    for col in STATLINE_COLS:  # a database from before these columns
        if col not in have:
            db.execute(f"ALTER TABLE statline ADD COLUMN {col} INT")
    return db


def meta_get(db, k, default=None):
    r = db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    return r[0] if r else default


def meta_set(db, k, v):
    db.execute("INSERT OR REPLACE INTO meta VALUES(?, ?)", (k, str(v)))


# --- ingest: events.log -> database ----------------------------------------------------------------------------------

STATLINE_RE = re.compile(
    r"users (\d+) local, (\d+) network \(peak \d+\) \| channels \d+ \(\d+ registered\) \| connections (\d+) \| "
    r"bans K(\d+) G(\d+) Z(\d+) \((\d+) DNSBL, (\d+) scanner\) \| DNSBL hits (\d+)"
    r"(?: \| scanner (\d+) scanned, (\d+) proxies[^|]*)?(?: ?\| spam filter (\d+) actions, (\d+) rules(?: \(filters off\))?)?"
    r".*?\| ircd ([\d.]+)% cpu (\d+)MB(?:.*\| sekurircd (\S+))?")
STATLINE_COLS = ("dnsbl_bans", "scan_bans", "scanned", "proxies", "spam", "spam_rules")


def read_log(path):
    """Everything appended so far, emptied under the same POSIX lock services/stats.c writes with."""
    try:
        fd = os.open(path, os.O_RDWR)
    except FileNotFoundError:
        return []
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX)
        data = b""
        while chunk := os.read(fd, 1 << 20):
            data += chunk
        os.ftruncate(fd, 0)
    finally:
        os.close(fd)  # releases the lock
    out = []
    for line in data.decode("utf-8", "replace").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            pass  # a torn line from a crash: skip it
    return out


def open_outage(db, name, uplink, t, reason):
    if not db.execute("SELECT 1 FROM outages WHERE name=? AND end IS NULL", (name,)).fetchone():
        db.execute("INSERT INTO outages(name, uplink, start, end, reason) VALUES(?,?,?,NULL,?)", (name, uplink, t, reason))


def close_outage(db, name, t):
    db.execute("UPDATE outages SET end=? WHERE name=? AND end IS NULL", (max(t, 0), name))


def apply_snapshot(db, net, srvs, end):
    t = int(net["t"])
    db.execute("INSERT OR REPLACE INTO net VALUES(?,?,?,?,?,?,?,?,?,?,?)",
               (t, net["users"], net["channels"], net["regchans"], net["opers"], net["away"], net["tls"],
                net["logged"], net["peak"], end.get("accounts", -1), end.get("regchans_cs", 0)))
    meta_set(db, "svc_start", int(end.get("svc_start", 0)))
    meta_set(db, "svc_version", end.get("svc_version", ""))
    meta_set(db, "hub_start", int(net.get("hub_start", 0)))
    meta_set(db, "last_snapshot", t)
    seen = {}
    for s in srvs:
        seen[s["name"]] = s
        db.execute("INSERT OR REPLACE INTO srv VALUES(?,?,?)", (t, s["name"], s["users"]))
        old = db.execute("SELECT linked_at, present FROM servers WHERE name=?", (s["name"],)).fetchone()
        if old is None:
            db.execute("INSERT INTO servers VALUES(?,?,?,?,?,?,?,?,1,?)",
                       (s["name"], s["sid"], s["uplink"], s["hop"], s["desc"], t, t, s["linked_at"], s["users"]))
            continue
        if old[1] == 0 or db.execute("SELECT 1 FROM outages WHERE name=? AND end IS NULL", (s["name"],)).fetchone():
            close_outage(db, s["name"], int(s["linked_at"]) if s["linked_at"] <= t else t)  # back: its LINK was missed
        elif old[0] and s["linked_at"] > old[0] and s["hop"] > 0 and not db.execute(
                "SELECT 1 FROM outages WHERE name=? AND start>=?", (s["name"], old[0])).fetchone():
            # relinked between two snapshots and both events were missed (the collector was off): a zero-length split
            db.execute("INSERT INTO outages(name, uplink, start, end, reason) VALUES(?,?,?,?,?)",
                       (s["name"], s["uplink"], s["linked_at"], s["linked_at"], "Relinked (split not seen)"))
        db.execute("UPDATE servers SET sid=?, uplink=?, hop=?, descr=?, last_seen=?, linked_at=?, present=1, users=? "
                   "WHERE name=?", (s["sid"], s["uplink"], s["hop"], s["desc"], t, s["linked_at"], s["users"], s["name"]))
    # Gone without a SPLIT of their own: behind a server that split (only the split server is announced).
    for name, uplink in db.execute("SELECT name, uplink FROM servers WHERE present=1").fetchall():
        if name in seen:
            continue
        root = db.execute("SELECT name, start, reason FROM outages WHERE start>=? AND start<=? ORDER BY start DESC LIMIT 1",
                          (t - 600, t)).fetchone()
        start, reason = (root[1], f"Behind {root[0]}: {root[2]}") if root else (t, "Missing from the network")
        open_outage(db, name, uplink, start, reason)
        db.execute("UPDATE servers SET present=0, users=0 WHERE name=?", (name,))


def ingest_records(db, recs):
    snap = None
    for r in recs:
        k, t = r.get("k"), int(r.get("t", 0))
        if k == "net":
            snap = (r, [])
        elif k == "srv" and snap:
            snap[1].append(r)
        elif k == "end" and snap:
            apply_snapshot(db, snap[0], snap[1], r)
            snap = None
        elif k == "split":
            open_outage(db, r["name"], r.get("uplink", "-"), t, r.get("reason", ""))
            db.execute("UPDATE servers SET present=0, users=0 WHERE name=?", (r["name"],))
        elif k == "link":
            close_outage(db, r["name"], t)
            if not db.execute("UPDATE servers SET present=1, uplink=?, descr=?, linked_at=? WHERE name=?",
                              (r.get("uplink", "-"), r.get("desc", ""), t, r["name"])).rowcount:
                db.execute("INSERT INTO servers VALUES(?,?,?,?,?,?,?,?,1,0)",
                           (r["name"], "", r.get("uplink", "-"), 1, r.get("desc", ""), t, t, t))
        elif k == "ban":
            db.execute("INSERT INTO bans VALUES(?,?,?,?,?,?)",
                       (t, r.get("type", "?"), r.get("by", ""), int(r.get("dur", 0)), r.get("mask", ""), r.get("reason", "")))
        elif k == "statline":
            m = STATLINE_RE.search(r.get("text", ""))
            if m:
                (local, _net, conns, kl, gl, zl, dnsbl_bans, scan_bans, dnsbl, scanned, proxies, spam, rules,
                 cpu, mem, ver) = m.groups()
                num = lambda v: int(v) if v is not None else None
                db.execute("INSERT OR REPLACE INTO statline(t, name, cpu, mem, conns, dnsbl, kl, gl, zl, local, version, "
                           "dnsbl_bans, scan_bans, scanned, proxies, spam, spam_rules) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (t, r["name"], float(cpu), int(mem), int(conns), int(dnsbl), int(kl), int(gl), int(zl),
                            int(local), ver or "", int(dnsbl_bans), int(scan_bans), num(scanned), num(proxies), num(spam),
                            num(rules)))
        elif k in ("svc", "session"):
            ev = r.get("ev", "")
            db.execute("INSERT INTO svc VALUES(?,?,?)", (t, ev if k == "svc" else "link-" + ev, r.get("version", "")))


def rollup(db, now):
    h0 = (int(now) // HOUR - 2) * HOUR
    db.execute("INSERT OR REPLACE INTO net_h SELECT (t/3600)*3600 AS h, MIN(users), AVG(users), MAX(users), MAX(accounts), "
               "AVG(channels) FROM net WHERE t>=? GROUP BY h", (h0,))
    d0 = (int(now) // DAY - 2) * DAY
    db.execute("INSERT OR REPLACE INTO net_d SELECT (t/86400)*86400 AS d, MIN(umin), AVG(uavg), MAX(umax), MAX(accounts), "
               "AVG(channels) FROM net_h WHERE t>=? GROUP BY d", (d0,))


def retention(db, c, now):
    for table, days in (("net", RAW_DAYS), ("srv", RAW_DAYS), ("net_h", HOURLY_DAYS), ("statline", STATLINE_DAYS),
                        ("net_d", c["retention"]), ("bans", c["retention"]), ("svc", c["retention"])):
        db.execute(f"DELETE FROM {table} WHERE t<?", (now - days * DAY,))
    db.execute("DELETE FROM outages WHERE end IS NOT NULL AND end<?", (now - c["retention"] * DAY,))
    db.execute("DELETE FROM servers WHERE present=0 AND last_seen<?", (now - c["retention"] * DAY,))


def ingest(c, db=None):
    own = db is None
    db = db or open_db(c)
    now = time.time()
    recs = read_log(c["log"])
    with db:
        ingest_records(db, recs)
        rollup(db, now)
        retention(db, c, now)
    if own:
        db.close()
    return len(recs)


# --- outside checks: ports + certificates, and where each server is -------------------------------------------------

def server_host(c, name):
    o = c["servers"].get(name.lower(), {})
    return o.get("host") or name


def cert_days_left(der):
    """Days until notAfter of a DER certificate (stdlib only: decode through a temporary PEM file)."""
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(ssl.DER_cert_to_PEM_cert(der))
    try:
        info = ssl._ssl._test_decode_cert(f.name)  # noqa: SLF001 -- the only stdlib decoder; fine for a read-only probe
        return int((ssl.cert_time_to_seconds(info["notAfter"]) - time.time()) // DAY)
    except Exception:
        return None
    finally:
        os.unlink(f.name)


def probe(host, port, use_tls, timeout):
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            if not use_tls:
                return 1, (time.time() - t0) * 1000, "", None
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # we report trust separately below; an expiring self-signed cert still counts
            with ctx.wrap_socket(s, server_hostname=host) as ts:
                ms = (time.time() - t0) * 1000
                der = ts.getpeercert(binary_form=True)
            err = ""
            try:  # is it trusted by the system store?
                v = ssl.create_default_context()
                with socket.create_connection((host, port), timeout=timeout) as s2, v.wrap_socket(s2, server_hostname=host):
                    pass
            except ssl.SSLCertVerificationError as e:
                err = "untrusted certificate: " + (e.verify_message or "verify failed")
            except OSError:
                pass
            return 1, ms, err, cert_days_left(der) if der else None
    except (OSError, ssl.SSLError) as e:
        return 0, None, (str(e) or e.__class__.__name__)[:120], None


def run_probes(c, db):
    names = [r[0] for r in db.execute("SELECT name FROM servers WHERE last_seen>=?", (time.time() - 30 * DAY,))]
    for name in names:
        o = c["servers"].get(name.lower(), {})
        if o.get("hide"):
            continue
        host = server_host(c, name)
        for port in [int(p) for p in o.get("ports", c["health"]["ports"])]:
            ok, ms, err, days = probe(host, port, port in c["health"]["tls_ports"], c["health"]["timeout"])
            with db:
                db.execute("INSERT OR REPLACE INTO probes VALUES(?,?,?,?,?,?,?,?)",
                           (name, port, int(time.time()), ok, ms, err, int(port in c["health"]["tls_ports"]), days))


def geoip_lookup(path, ips):
    """{ip: (city, country, lat, lon)} from a DB-IP Lite city CSV (.csv or .csv.gz). One pass over the file for all."""
    want = {}
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
            want[ip] = (a.version, int(a))
        except ValueError:
            pass
    found = {}
    if not want or not os.path.exists(path):
        return found
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            if len(found) == len(want):
                break
            parts = line.rstrip("\n").split(",")
            if len(parts) < 8:
                continue
            v6 = ":" in parts[0]
            for ip, (ver, n) in want.items():
                if ip in found or (ver == 6) != v6:
                    continue
                try:
                    if int(ipaddress.ip_address(parts[0])) <= n <= int(ipaddress.ip_address(parts[1])):
                        city = parts[5].strip('"') if len(parts) == 8 else ",".join(parts[5:-2]).strip('"')
                        found[ip] = (city, parts[3], float(parts[-2]), float(parts[-1]))
                except ValueError:
                    pass
    return found


def resolve_locations(c, db):
    """Fill the geo table for servers that have no cached or configured location."""
    todo = {}
    for (name,) in db.execute("SELECT name FROM servers"):
        o = c["servers"].get(name.lower(), {})
        if "lat" in o:
            continue
        host = server_host(c, name)
        if db.execute("SELECT 1 FROM geo WHERE host=? AND t>?", (host, time.time() - 7 * DAY)).fetchone():
            continue
        try:
            ip = socket.getaddrinfo(host, None)[0][4][0]
        except OSError:
            ip = ""
        todo[host] = ip
    if not todo:
        return
    public = {h: ip for h, ip in todo.items() if ip and ipaddress.ip_address(ip).is_global}
    found = geoip_lookup(c["geoip"], set(public.values()))
    with db:
        for host, ip in todo.items():
            city, country, lat, lon = found.get(ip, ("", "", None, None))
            db.execute("INSERT OR REPLACE INTO geo VALUES(?,?,?,?,?,?,?)", (host, ip, city, country, lat, lon, int(time.time())))


def geoip_update(c):
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    url = f"https://download.db-ip.com/free/dbip-city-lite-{month}.csv.gz"
    tmp = c["geoip"] + ".part"
    print(f"downloading {url}\n  -> {c['geoip']}")
    req = urllib.request.Request(url, headers={"User-Agent": "netstats"})
    with urllib.request.urlopen(req, timeout=120) as r, open(tmp, "wb") as f:
        while chunk := r.read(1 << 20):
            f.write(chunk)
    os.replace(tmp, c["geoip"])
    print("done -- locations are looked up again within a week, or now with: rm the geo cache (DELETE FROM geo)")


# --- page data -------------------------------------------------------------------------------------------------------

def series(db, since, bucket, table="net", col="users"):
    if table == "net":
        q = f"SELECT (t/{bucket})*{bucket} AS b, AVG({col}) FROM net WHERE t>=? GROUP BY b ORDER BY b"
    else:
        q = f"SELECT (t/{bucket})*{bucket} AS b, AVG(uavg) FROM {table} WHERE t>=? GROUP BY b ORDER BY b"
    return [[int(b), round(v)] for b, v in db.execute(q, (since,)) if v is not None]


def build(c, db, role, now=None):
    now = int(now or time.time())
    admin = role == "admin"
    d30 = now - 30 * DAY
    last = db.execute("SELECT * FROM net ORDER BY t DESC LIMIT 1").fetchone()
    cols = ["t", "users", "channels", "regchans", "opers", "away", "tls", "logged", "peak", "accounts", "regchans_cs"]
    cur = dict(zip(cols, last)) if last else None
    first_t = (db.execute("SELECT MIN(t) FROM net_h").fetchone()[0] or now)
    peak = db.execute("SELECT umax, t FROM net_h WHERE t>=? ORDER BY umax DESC LIMIT 1", (d30,)).fetchone()

    # servers, their places and their outside checks
    rows = db.execute("SELECT name, sid, uplink, hop, descr, first_seen, last_seen, linked_at, present, users FROM servers "
                      "WHERE present=1 OR last_seen>=? ORDER BY hop, name", (d30,)).fetchall()
    uplinks = {r[2] for r in rows}
    servers = []
    for name, sid, uplink, hop, descr, fs, ls, linked_at, present, users in rows:
        o = c["servers"].get(name.lower(), {})
        if o.get("hide"):
            continue
        host = server_host(c, name)
        g = db.execute("SELECT ip, city, country, lat, lon FROM geo WHERE host=?", (host,)).fetchone()
        loc, lat, lon, ip = "", None, None, (g[0] if g else "")
        if "lat" in o:
            lat, lon, loc = float(o["lat"]), float(o["lon"]), o.get("location", "")
        elif g and g[3] is not None:
            lat, lon, loc = g[3], g[4], ", ".join(x for x in (g[1], g[2]) if x)
        if o.get("location"):
            loc = o["location"]
        sl = db.execute("SELECT t, cpu, mem, version, conns FROM statline WHERE name=? ORDER BY t DESC LIMIT 1",
                        (name,)).fetchone()
        fresh = sl and sl[0] >= now - 3 * HOUR
        servers.append({
            "name": name, "uplink": uplink, "hop": hop, "desc": descr, "present": bool(present),
            "hub": hop == 0 or name in uplinks, "users": users if present else 0, "linked_at": linked_at,
            "loc": loc, "lat": lat, "lon": lon, "ip": ip if admin else "",
            "cpu": sl[1] if fresh else None, "mem": sl[2] if fresh else None,
            "version": (sl[3] if sl else "") or "",
            "probes": [{"port": p, "ok": bool(ok), "ms": ms, "err": err if admin or ok else "unreachable", "tls": bool(tls),
                        "cert_days": days, "t": pt}
                       for p, ok, ms, err, tls, days, pt in db.execute(
                           "SELECT port, ok, ms, err, tls, cert_days, t FROM probes WHERE name=? ORDER BY port", (name,))],
        })
    names = {s["name"] for s in servers}
    hub0 = next((s["name"] for s in servers if s["hop"] == 0), None)

    def outages_of(name, since):
        return [[a, b, r] for a, b, r in db.execute(
            "SELECT start, end, reason FROM outages WHERE name=? AND (end IS NULL OR end>=?) ORDER BY start", (name, since))]

    links = [{"a": s["name"], "b": s["uplink"], "kind": "hub" if s["hub"] and s["uplink"] in names and
              next((x["hub"] for x in servers if x["name"] == s["uplink"]), False) else "leaf",
              "outages": outages_of(s["name"], now - 365 * DAY), "present": s["present"]}
             for s in servers if s["uplink"] not in ("-", "") and s["hop"] > 0]

    # services: link sessions and restarts -> its own outages
    svc_ev = db.execute("SELECT t, ev FROM svc WHERE t>=? ORDER BY t", (now - 365 * DAY,)).fetchall()
    svc_out, down_at, restarts = [], None, 0
    for t, ev in svc_ev:
        if ev in ("stop", "link-down") and down_at is None:
            down_at = t
        elif ev in ("start", "link-up"):
            if ev == "start":
                restarts += t >= d30
            if down_at is not None:
                svc_out.append([down_at, t, "Services restart" if ev == "start" else "Services link lost"])
                down_at = None
    last_snap = int(meta_get(db, "last_snapshot", 0) or 0)
    svc_up = last_snap >= now - max(3 * c["sample"], 180)
    if not svc_up:
        svc_out.append([down_at or last_snap or now, None, "No data from services"])
    if hub0:
        links.insert(0, {"a": "services", "b": hub0, "kind": "services", "outages": svc_out, "present": svc_up})

    def avail(since):
        span = now - max(since, first_t)
        if span <= 0 or not links:
            return None
        down = 0
        for l in links:
            for a, b, _ in l["outages"]:
                down += max(0, min(b or now, now) - max(a, since))
        return max(0.0, 1 - down / (span * len(links)))

    incidents = []
    for l in links:
        for a, b, r in l["outages"]:
            if (b or now) >= now - 365 * DAY:
                incidents.append({"a": l["a"], "b": l["b"], "start": a, "end": b, "reason": r, "kind": l["kind"]})
    incidents.sort(key=lambda x: -x["start"])

    # connections per hour of the week, from the per-server "connections" counters in the stats lines
    heat, weeks = [[0] * 24 for _ in range(7)], set()
    prev = {}
    have = False
    for t, name, conns in db.execute("SELECT t, name, conns FROM statline WHERE t>=? ORDER BY t", (now - 28 * DAY,)):
        p = prev.get(name)
        prev[name] = (t, conns)
        if not p or t - p[0] > 2 * HOUR:
            continue
        have = True
        d = conns - p[1] if conns >= p[1] else conns
        dt = datetime.fromtimestamp(t, timezone.utc)
        heat[dt.weekday()][dt.hour] += d
        weeks.add(dt.isocalendar()[:2])
    heat = [[round(v / max(1, len(weeks))) for v in row] for row in heat] if have else None

    daily_acc = db.execute("SELECT (t/86400)*86400 AS d, MAX(accounts) FROM net_h WHERE t>=? AND accounts>=0 GROUP BY d "
                           "ORDER BY d", (now - 31 * DAY,)).fetchall()
    regs = [{"t": d, "reg": max(0, a - daily_acc[i - 1][1])} for i, (d, a) in enumerate(daily_acc) if i > 0]

    data = {
        "role": role, "network": c["network"], "now": now, "public": c["http"]["public"],
        "sample": c["sample"], "retention": c["retention"], "first": first_t,
        "cur": cur, "peak30": list(peak) if peak else None,
        "series": {"1": series(db, now - DAY, 300), "7": series(db, now - 7 * DAY, HOUR),
                   "30": series(db, now - 30 * DAY, 2 * HOUR, "net_h"), "365": series(db, now - 365 * DAY, DAY, "net_d")},
        "servers": servers, "links": links, "incidents": incidents[:200],
        "avail30": avail(d30), "heat": heat,
        "services": {"up": svc_up, "version": meta_get(db, "svc_version", ""), "start": int(meta_get(db, "svc_start", 0) or 0),
                     "restarts30": restarts, "accounts": [[d, a] for d, a in daily_acc], "regs": regs},
        "geoip": os.path.exists(c["geoip"]),
    }
    if admin:
        bans = db.execute("SELECT (t/86400)*86400 AS d, type, by, COUNT(*) FROM bans WHERE t>=? GROUP BY d, type, by",
                          (now - 30 * DAY,)).fetchall()
        days = {}
        for d, typ, by, n in bans:
            e = days.setdefault(d, {"t": d})
            e[typ] = e.get(typ, 0) + n
            src = by if by in ("dnsbl", "protection", "spam", "connect-flood") else "manual"
            e["src_" + src] = e.get("src_" + src, 0) + n
        hub_sl = db.execute("SELECT kl, gl, zl, dnsbl FROM statline WHERE name=? ORDER BY t DESC LIMIT 1",
                            (hub0 or "",)).fetchone()
        prev = {}  # counters since each server started: a per-day delta, a restart (counter went down) starts over
        for row in db.execute("SELECT t, name, dnsbl, scanned, proxies, spam FROM statline WHERE t>=? ORDER BY t",
                              (now - 31 * DAY,)):
            t, name, vals = row[0], row[1], row[2:]
            p = prev.get(name)
            prev[name] = vals
            if p is None:
                continue
            e = days.setdefault((t // DAY) * DAY, {"t": (t // DAY) * DAY})
            for key, v, pv in zip(("dnsbl_hits", "scanned", "proxies", "spam_actions"), vals, p):
                if v is not None and pv is not None:
                    e[key] = e.get(key, 0) + (v - pv if v >= pv else v)
        prot = []
        for name, in db.execute("SELECT DISTINCT name FROM statline WHERE t>=?", (now - 3 * HOUR,)):
            r = db.execute("SELECT dnsbl_bans, scan_bans, scanned, proxies, spam, spam_rules, dnsbl FROM statline "
                           "WHERE name=? ORDER BY t DESC LIMIT 1", (name,)).fetchone()
            prot.append({"name": name, "dnsbl_bans": r[0], "scan_bans": r[1], "scanned": r[2], "proxies": r[3],
                         "spam": r[4], "spam_rules": r[5], "dnsbl_hits": r[6]})
        data["security"] = {
            "days": [days[k] for k in sorted(days)],
            "active": {"K": hub_sl[0], "G": hub_sl[1], "Z": hub_sl[2]} if hub_sl else None,
            "recent": [{"t": t, "type": typ, "by": by, "dur": dur, "mask": mask, "reason": reason} for t, typ, by, dur, mask, reason
                       in db.execute("SELECT t, type, by, dur, mask, reason FROM bans ORDER BY t DESC LIMIT 15")],
            "today": db.execute("SELECT COUNT(*) FROM bans WHERE t>=?", (now - now % DAY,)).fetchone()[0],
            "servers": sorted(prot, key=lambda p: p["name"]),
        }
    return data


def render(c, db, role, now=None, live=False):
    """The page for `role`; live = served by the panel (shows Log in / Log out), not written to a file for a website."""
    with open(os.path.join(ASSETS, "page.html"), encoding="utf-8") as f:
        page = f.read()
    with open(os.path.join(ASSETS, "world-110m.json"), encoding="utf-8") as f:
        world = f.read()
    d = build(c, db, role, now)
    d["live"] = live
    data = json.dumps(d, separators=(",", ":")).replace("</", "<\\/")
    return page.replace("/*@DATA@*/null", data, 1).replace("/*@MAP@*/null", world, 1)


def write_atomic(path, text):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def export(c, db):
    out = []
    for key, role in (("public_html", "viewer"), ("admin_html", "admin")):
        if c["export"][key]:
            write_atomic(c["export"][key], render(c, db, role))
            out.append(c["export"][key])
    return out


# --- web panel -------------------------------------------------------------------------------------------------------

class Panel:
    def __init__(self, c, log):
        self.c, self.log = c, log
        self.pages, self.lock = {}, threading.Lock()
        self.fails = {}  # ip -> [timestamps of failed logins]
        self.good = {}   # sha256(header) -> (role, expires): skip scrypt on every reload
        self.sessions = {}  # cookie token -> (login name, its password hash, expires): a logged-in browser

    def refresh(self, db):
        pages = {r: render(self.c, db, r, live=True).encode() for r in ROLES}
        with self.lock:
            self.pages = pages

    def worker(self):
        db = open_db(self.c)
        last_probe = last_geo = 0
        while True:
            try:
                ingest(self.c, db)
                now = time.time()
                if now - last_geo >= 6 * HOUR or not db.execute("SELECT 1 FROM geo").fetchone():
                    resolve_locations(self.c, db)
                    last_geo = now
                if now - last_probe >= self.c["health"]["interval"]:
                    run_probes(self.c, db)
                    last_probe = now
                self.refresh(db)
            except Exception as e:  # keep serving the last good page
                self.log(f"refresh failed: {e!r}")
            time.sleep(60)

    def reload_users(self):
        """--user --add/--del edits stats.toml: take its logins over without a restart (a bad edit keeps the old ones)."""
        try:
            m = os.stat(self.c["path"]).st_mtime
        except OSError:
            return
        if m != getattr(self, "conf_mtime", m):
            try:
                self.c["users"] = load_config(self.c["path"])["users"]
                self.good.clear()
                self.log(f"logins reloaded: {len(self.c['users'])}")
            except ConfigError as e:
                self.log(f"stats.toml changed but can't be loaded, keeping the old logins: {e}")
        self.conf_mtime = m

    def check(self, name, pw, ip):
        """The [[users]] entry for a good name + password, else None (counted against `ip`)."""
        for u in self.c["users"]:
            if hmac.compare_digest(u["name"].encode(), name.encode()) and check_password(pw, u["password"]):
                return u
        self.fails.setdefault(ip, []).append(time.time())
        self.log(f"failed login for '{name[:40]}' from {ip}")
        return None

    def auth(self, header, ip):
        """HTTP Basic (curl -u, scripts): 'admin' / 'viewer' for good credentials, None for none, False for bad ones."""
        self.reload_users()
        if not header or not header.startswith("Basic "):
            return None
        key = hashlib.sha256(header.encode()).hexdigest()
        hit = self.good.get(key)
        if hit and hit[1] > time.time():
            return hit[0]
        try:
            user, _, pw = base64.b64decode(header[6:]).decode().partition(":")
        except ValueError:
            return False
        u = self.check(user, pw, ip)
        if not u:
            return False
        self.good[key] = (u["role"], time.time() + 600)
        return u["role"]

    def session_start(self, u):
        now = time.time()
        for k in [k for k, v in list(self.sessions.items()) if v[2] <= now]:
            self.sessions.pop(k, None)
        tok = secrets.token_urlsafe(32)
        self.sessions[tok] = (u["name"], u["password"], now + SESSION_TTL)
        return tok

    def cookie(self, token, age=SESSION_TTL):
        h = self.c["http"]
        # Secure when the browser is on HTTPS: our own certificate, or the reverse proxy that [http] hostname names
        return (f"netstats_session={token}; Path=/; Max-Age={age}; HttpOnly; SameSite=Strict"
                + ("; Secure" if h["tls_cert"] or h["hostname"] else ""))

    def login_page(self, error=""):
        err = f'<div class="err" role="alert">{html.escape(error)}</div>\n' if error else ""
        back = '<p><a href="/">Back to the public page</a></p>\n' if self.c["http"]["public"] else ""
        return (LOGIN_PAGE.replace("/*NET*/", html.escape(self.c["network"])).replace("/*ERR*/", err)
                .replace("/*BACK*/", back).encode())

    @staticmethod
    def session_token(cookie):
        m = re.search(r"(?:^|;\s*)netstats_session=([\w-]+)", cookie or "")
        return m.group(1) if m else None

    def session_role(self, cookie):
        """The role of the browser's login session, None when it has none (or its login was removed / changed password)."""
        self.reload_users()
        s = self.sessions.get(self.session_token(cookie))
        if not s or s[2] <= time.time():
            return None
        for u in self.c["users"]:
            if u["name"] == s[0] and u["password"] == s[1]:
                return u["role"]
        return None

    def client_ip(self, peer, xff):
        """The visitor's address: the proxy's X-Forwarded-For entry when the request comes from a trusted proxy (Caddy,
        nginx), else the socket peer -- so failed logins behind a proxy count per visitor, not for everyone at once."""
        if xff and peer in self.c["http"]["trusted_proxies"]:
            last = xff.split(",")[-1].strip()  # what our proxy saw; earlier entries are the client's to forge
            try:
                return str(ipaddress.ip_address(last))
            except ValueError:
                pass
        return peer

    def throttled(self, ip):
        recent = [t for t in self.fails.get(ip, []) if t > time.time() - 600]
        self.fails[ip] = recent
        return len(recent) >= 10

    def handler(panel):
        class H(http.server.BaseHTTPRequestHandler):
            server_version = "netstats"
            sys_version = ""

            def log_message(self, format, *args):  # noqa: A002 -- the base class's name
                pass

            def send(self, code, body=b"", ctype="text/plain; charset=utf-8", extra=()):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; "
                                 "style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'self'")
                for k, v in extra:
                    self.send_header(k, v)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def challenge(self):
                self.send(401, b"Login required\n", extra=[("WWW-Authenticate", 'Basic realm="netstats", charset="UTF-8"')])

            def do_HEAD(self):
                self.do_GET()

            def go(self, where, code=302, extra=()):
                self.send(code, extra=[("Location", where), *extra])

            def do_GET(self):
                ip = panel.client_ip(self.client_address[0], self.headers.get("X-Forwarded-For"))
                path = self.path.split("?", 1)[0]
                if path == "/healthz":
                    return self.send(200, b"ok\n")
                if path == "/admin":
                    return self.go("/admin/", 301)
                if path not in ("/", "/admin/", "/login"):
                    return self.send(404, b"Not found\n")
                if panel.throttled(ip):
                    return self.send(429, b"Too many failed logins, try again later\n")
                session = panel.session_role(self.headers.get("Cookie"))
                if path == "/login":  # the form; a browser that is logged in already goes on to the page
                    return self.go("/admin/") if session else self.send(200, panel.login_page(), "text/html; charset=utf-8")
                # /admin/ is the logged-in page (always asks); / is the viewer page for everyone when public = true.
                # A browser with a login session always lives at /admin/, where the page shows Log out.
                if session and path == "/":
                    return self.go("/admin/")
                role = session or panel.auth(self.headers.get("Authorization"), ip)  # else HTTP Basic: curl -u
                if role is False:
                    return self.challenge()
                if role is None and (path == "/admin/" or not panel.c["http"]["public"]):
                    return self.go("/login")
                with panel.lock:
                    page = panel.pages.get(role or "viewer")
                if page is None:
                    return self.send(503, b"Starting up, reload in a moment\n")
                self.send(200, page, "text/html; charset=utf-8")

            def do_POST(self):
                ip = panel.client_ip(self.client_address[0], self.headers.get("X-Forwarded-For"))
                path = self.path.split("?", 1)[0]
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    return self.send(400, b"Bad request\n")
                if n > 4096:
                    return self.send(413, b"Too big\n")
                form = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
                if path == "/logout":  # POST only: a link or image on another site can't log anyone out
                    panel.sessions.pop(panel.session_token(self.headers.get("Cookie")), None)
                    return self.go("/" if panel.c["http"]["public"] else "/login", 303, [("Set-Cookie", panel.cookie("", 0))])
                if path != "/login":
                    return self.send(404, b"Not found\n")
                if panel.throttled(ip):
                    return self.send(429, b"Too many failed logins, try again later\n")
                panel.reload_users()
                u = panel.check(form.get("user", [""])[0], form.get("password", [""])[0], ip)
                if not u:
                    # 200, not 401: a 401 must carry WWW-Authenticate, which would pop up the browser's own login box
                    return self.send(200, panel.login_page("Wrong name or password."), "text/html; charset=utf-8")
                self.go("/admin/", 303, [("Set-Cookie", panel.cookie(panel.session_start(u)))])
        return H

    def serve(self):
        h = self.c["http"]
        if not self.c["users"] and not h["public"]:
            raise ConfigError("no [[users]] and public = false: nobody could open the panel")
        db = open_db(self.c)
        ingest(self.c, db)
        self.refresh(db)
        db.close()
        threading.Thread(target=self.worker, daemon=True).start()
        family = socket.AF_INET6 if ":" in h["bind"] else socket.AF_INET

        class Srv(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True
            address_family = family
            request_queue_size = 64

        httpd = Srv((h["bind"], h["port"]), self.handler())
        if h["tls_cert"]:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(h["tls_cert"], h["tls_key"])
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        self.log(f"serving on {'https' if h['tls_cert'] else 'http'}://{h['bind']}:{h['port']}/ "
                 f"({len(self.c['users'])} logins, public={h['public']})")
        if h["hostname"]:
            self.log(f"public address: https://{h['hostname']}/admin/ (through your reverse proxy)")
        for n in exposure_notes(h):
            self.log(n)
        httpd.serve_forever()


# --- daemon plumbing (mirrors the ircd's --daemon/--stop/--pidfile) ---------------------------------------------------

def exposure_notes(h):
    """What to tell an admin about a panel bound beyond localhost: the firewall, and clear-text logins without TLS."""
    if h["bind"] in ("127.0.0.1", "::1", "localhost"):
        return caddy_notes(h)
    port = h["port"]
    notes = [f"bound to {h['bind']}: reachable from outside only if TCP {port} is open in the firewall:",
             f"  ufw:        sudo ufw allow {port}/tcp",
             f"  firewalld:  sudo firewall-cmd --permanent --add-port={port}/tcp && sudo firewall-cmd --reload",
             f"  iptables:   sudo iptables -I INPUT -p tcp --dport {port} -j ACCEPT   (persist: netfilter-persistent save)",
             f"  pf (BSD/macOS): add 'pass in proto tcp to port {port}' to /etc/pf.conf, then sudo pfctl -f /etc/pf.conf",
             "  and in your provider's firewall / security group, if it has one"]
    if not h["tls_cert"]:
        notes.append("WARNING: no tls_cert: logins cross the network in clear text -- set tls_cert/tls_key, "
                     "or bind 127.0.0.1 behind an HTTPS reverse proxy")
    return notes


def caddy_notes(h):
    """With [http] hostname set: the Caddyfile block that puts the panel on https://hostname/ (Caddy gets the cert)."""
    if not h.get("hostname"):
        return []
    host, port = h["hostname"], h["port"]
    return [f"to serve it at https://{host}/ with Caddy (automatic HTTPS), add to /etc/caddy/Caddyfile:",
            f"    {host} {{",
            f"        reverse_proxy 127.0.0.1:{port}",
            "    }",
            "  then: sudo systemctl reload caddy",
            f"  DNS: an A/AAAA record for {host} pointing at this server; TCP 80 and 443 open in the firewall"]


def pid_alive(pidfile):
    try:
        pid = int(open(pidfile).read().strip())
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError):
        return 0


def daemonize(pidfile, logfile):
    if os.fork():
        os._exit(0)
    os.setsid()
    if os.fork():
        os._exit(0)
    os.makedirs(os.path.dirname(logfile), exist_ok=True)
    fd = os.open(logfile, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
    nul = os.open(os.devnull, os.O_RDONLY)
    os.dup2(nul, 0)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    with open(pidfile, "w") as f:
        f.write(f"{os.getpid()}\n")
    signal.signal(signal.SIGTERM, lambda *a: (os.path.exists(pidfile) and os.unlink(pidfile), os._exit(0)))


def stop(pidfile):
    pid = pid_alive(pidfile)
    if not pid:
        print(f"netstats: not running (pidfile {pidfile})")
        return 0
    os.kill(pid, signal.SIGTERM)
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except OSError:
            print(f"netstats: stopped (pid {pid})")
            return 0
        time.sleep(0.1)
    print(f"netstats: pid {pid} did not stop", file=sys.stderr)
    return 1


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S ") + msg, flush=True)


# --- logins: [[users]] blocks in stats.toml, edited as text so comments and layout stay ---------------------------------

NAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,40}$")


def user_blocks(lines):
    """[(start, end, user dict)] for every [[users]] table; end stops before the next table and its leading comments."""
    out, i = [], 0
    while i < len(lines):
        if re.match(r"^\s*\[\[\s*users\s*\]\]", lines[i]):
            j = i + 1
            while j < len(lines) and not re.match(r"^\s*\[", lines[j]):
                j += 1
            k = j
            while k > i + 1 and (not lines[k - 1].strip() or lines[k - 1].lstrip().startswith("#")):
                k -= 1
            try:
                u = tomllib.loads("".join(lines[i:k]))["users"][0]
            except (tomllib.TOMLDecodeError, KeyError, IndexError):
                u = {}
            out.append((i, k, u))
            i = j
        else:
            i += 1
    return out


def save_config_text(path, text):
    """Write stats.toml only if the result still loads; 0600, it holds password hashes."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, 0o600)
    try:
        load_config(tmp)
    except ConfigError as e:
        os.unlink(tmp)
        raise ConfigError(f"not saved, the result would be invalid: {e}")
    os.replace(tmp, path)


def user_add(path, name, role, pw_hash):
    if not NAME_RE.match(name):
        raise ConfigError("login names are 1-40 of A-Z a-z 0-9 _ . @ -")
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()
    for _, _, u in user_blocks(lines):
        if u.get("name") == name:
            raise ConfigError(f"'{name}' already exists ({u.get('role', 'viewer')}) -- --del it first to change it")
    text = "".join(lines)
    if text and not text.endswith("\n"):
        text += "\n"
    text += f'\n[[users]]\nname = "{name}"\npassword = "{pw_hash}"\nrole = "{role}"\n'
    save_config_text(path, text)


def user_del(path, name, role):
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()
    for s, e, u in user_blocks(lines):
        if u.get("name") != name:
            continue
        if u.get("role", "viewer") != role:
            raise ConfigError(f"'{name}' is a{'n' if u.get('role', 'viewer') == 'admin' else ''} {u.get('role', 'viewer')}, "
                              f"not a{'n' if role == 'admin' else ''} {role} -- use --{u.get('role', 'viewer')}")
        while e < len(lines) and not lines[e].strip():  # and the blank line after it
            e += 1
        save_config_text(path, "".join(lines[:s] + lines[e:]))
        return
    raise ConfigError(f"no login named '{name}'")


def user_status(c, role=None):
    users = [u for u in c["users"] if role in (None, u["role"])]
    if not users:
        print(f"no {role or ''} logins in {c['path']}".replace("  ", " "))
    for u in sorted(users, key=lambda u: (u["role"], u["name"])):
        print(f"  {u['role']:<7} {u['name']}")
    h = c["http"]
    print(f"panel: {'https' if h['tls_cert'] else 'http'}://{h['bind']}:{h['port']}/  "
          f"(public = {str(h['public']).lower()}: {'anyone gets the viewer page' if h['public'] else 'login required'})")


def ask_password():
    pw = getpass.getpass("password: ")
    if len(pw) < 8:
        raise ConfigError("use at least 8 characters")
    if pw != getpass.getpass("again:    "):
        raise ConfigError("the two passwords differ")
    return hash_password(pw)


# --- selftest --------------------------------------------------------------------------------------------------------

def selftest():
    """Synthetic collector output -> ingest -> outages/rollups -> both pages; no network, no daemons."""
    d = tempfile.mkdtemp(prefix="netstats-selftest-")
    conf = os.path.join(d, "stats.toml")
    with open(conf, "w") as f:
        f.write('[collector]\nenabled = true\n[http]\nnetwork_name = "Test<Net>"\n'
                '[[servers]]\nname = "leaf.test"\nlat = 52.37\nlon = 4.9\nlocation = "Amsterdam, NL"\n')
    c = load_config(conf)
    now = int(time.time())
    t0 = now - 2 * HOUR
    recs = [{"t": t0 - 5, "k": "svc", "ev": "start", "version": "1.5.0"}, {"t": t0 - 4, "k": "session", "ev": "up"}]

    def snap(t, leaf=True, linked=t0):
        r = [{"t": t, "k": "net", "users": 10 + leaf * 5, "channels": 3, "regchans": 1, "opers": 1, "away": 2, "tls": 8,
              "logged": 4, "peak": 15, "hub_start": t0 - 100},
             {"t": t, "k": "srv", "name": "hub.test", "sid": "1HB", "uplink": "-", "hop": 0, "users": 10, "linked_at": t0 - 100,
              "synced": 1, "desc": "the hub"}]
        if leaf:
            r.append({"t": t, "k": "srv", "name": "leaf.test", "sid": "2LF", "uplink": "hub.test", "hop": 1, "users": 5,
                      "linked_at": linked, "synced": 1, "desc": "a <b>leaf</b>"})
        return r + [{"t": t, "k": "end", "accounts": 40, "regchans_cs": 1, "svc_start": t0 - 5, "svc_version": "1.5.0"}]

    for i in range(0, 60):
        recs += snap(t0 + i * 60)
    recs.append({"t": t0 + 3601, "k": "split", "name": "leaf.test", "uplink": "hub.test", "reason": "Ping timeout: 180 seconds"})
    recs += snap(t0 + 3660, leaf=False)
    recs.append({"t": t0 + 3700, "k": "link", "name": "leaf.test", "uplink": "hub.test", "desc": "a leaf"})
    recs += snap(t0 + 3720, linked=t0 + 3700)
    recs.append({"t": t0 + 3800, "k": "ban", "type": "Z", "by": "dnsbl", "dur": 3600, "mask": "203.0.113.9", "reason": "x</script>"})
    recs.append({"t": t0 + 3800, "k": "statline", "name": "hub.test", "text":
                 "users 10 local, 15 network (peak 15) | channels 3 (1 registered) | connections 120 | bans K1 G0 Z4 "
                 "(1 DNSBL, 0 scanner) | DNSBL hits 7 | scanner 50 scanned, 2 proxies, 0 in flight, 3 cached | spam filter 4 actions, "
                 "12 rules | ircd 0.4% cpu 21MB | sekurircd 1.3.3"})
    with open(c["log"], "w") as f:
        f.write("\n".join(json.dumps(r) for r in recs) + "\n{torn line\n")
    assert ingest(c) == len(recs), "every good line is read"
    assert os.path.getsize(c["log"]) == 0, "the log is emptied"
    db = open_db(c)
    out = db.execute("SELECT name, start, end, reason FROM outages").fetchall()
    assert out == [("leaf.test", t0 + 3601, t0 + 3700, "Ping timeout: 180 seconds")], out
    assert db.execute("SELECT version, scanned, proxies, spam, spam_rules, dnsbl_bans FROM statline").fetchone() == \
        ("1.3.3", 50, 2, 4, 12, 1)
    assert db.execute("SELECT COUNT(*) FROM net_h").fetchone()[0] >= 1
    viewer, admin = build(c, db, "viewer", now), build(c, db, "admin", now)
    assert "security" not in viewer and "security" in admin
    assert all(s["ip"] == "" for s in viewer["servers"])
    leaf = next(s for s in admin["servers"] if s["name"] == "leaf.test")
    assert leaf["lat"] == 52.37 and leaf["present"]
    assert viewer["links"][0]["kind"] == "services" and viewer["links"][1]["outages"][0][2].startswith("Ping")
    page = render(c, db, "admin", now)
    assert "x<\\/script>" in page and "x</script>" not in page, "JSON can't close the script tag"
    assert "/*@DATA@*/" not in page and "/*@MAP@*/" not in page
    h = hash_password("pw")
    assert check_password("pw", h) and not check_password("px", h)
    user_add(conf, "alice", "admin", h)
    user_add(conf, "bob", "viewer", h)
    assert [(u["name"], u["role"]) for u in load_config(conf)["users"]] == [("alice", "admin"), ("bob", "viewer")]
    for bad in (lambda: user_add(conf, "alice", "viewer", h), lambda: user_del(conf, "bob", "admin"),
                lambda: user_del(conf, "nobody", "admin"), lambda: user_add(conf, 'x"y', "admin", h)):
        try:
            bad()
            raise AssertionError("should have been refused")
        except ConfigError:
            pass
    user_del(conf, "alice", "admin")
    left = open(conf).read()
    assert [u["name"] for u in load_config(conf)["users"]] == ["bob"] and "[[servers]]" in left and "alice" not in left
    h = {"bind": "127.0.0.1", "port": 8089, "tls_cert": ""}
    assert exposure_notes(h) == []
    n = exposure_notes(dict(h, bind="0.0.0.0", port=9443))
    assert "ufw allow 9443/tcp" in n[1] and n[-1].startswith("WARNING")
    assert not exposure_notes(dict(h, bind="0.0.0.0", tls_cert="c.pem"))[-1].startswith("WARNING")
    assert not caddy_notes(h) and "reverse_proxy 127.0.0.1:8089" in exposure_notes(dict(h, hostname="stats.ex.net"))[2]
    p = Panel.__new__(Panel)
    p.c = {"http": {"trusted_proxies": ["127.0.0.1"]}}
    assert p.client_ip("127.0.0.1", "6.6.6.6, 198.51.100.7") == "198.51.100.7"  # rightmost = what our proxy saw
    assert p.client_ip("203.0.113.9", "198.51.100.7") == "203.0.113.9"           # not a proxy: header ignored
    assert p.client_ip("127.0.0.1", "junk") == "127.0.0.1"
    with tempfile.TemporaryDirectory() as d:
        f = os.path.join(d, "s.toml")
        open(f, "w").write('[http]\nhostname = "Stats.Example.NET"\npublic = true\n')
        assert load_config(f)["http"]["trusted_proxies"] == ["127.0.0.1", "::1"]
        open(f, "w").write('[http]\nhostname = "not a host"\n')
        try:
            load_config(f); assert False
        except ConfigError:
            pass
    # the login form against a real in-process panel: wrong password, session cookie, logout, removed login
    c2 = load_config(conf)  # bob (viewer, password "pw")
    c2["http"]["public"] = True
    pn = Panel(c2, lambda m: None)
    pn.pages = {r: b"page-" + r.encode() for r in ROLES}
    httpd = http.server.HTTPServer(("127.0.0.1", 0), pn.handler())
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    def req(path, data=None, cookie=None):
        r = urllib.request.Request(f"http://127.0.0.1:{httpd.server_address[1]}{path}", headers={"Cookie": cookie or ""},
                                   data=None if data is None else data.encode())
        try:
            with urllib.request.build_opener(NoRedirect).open(r) as x:
                return x.status, x.headers, x.read()
        except urllib.error.HTTPError as e:  # a redirect we refused to follow
            return e.code, e.headers, e.read()

    assert req("/admin/")[0] == 302 and req("/admin/")[1]["Location"] == "/login"
    assert req("/")[2] == b"page-viewer" and b'name="password"' in req("/login")[2]
    st, hd, body = req("/login", "user=bob&password=nope")
    assert st == 200 and b"Wrong name or password" in body and "Set-Cookie" not in hd
    st, hd, _ = req("/login", "user=bob&password=pw")
    ck = hd["Set-Cookie"].split(";")[0]
    assert st == 303 and hd["Location"] == "/admin/" and "HttpOnly" in hd["Set-Cookie"] and "SameSite=Strict" in hd["Set-Cookie"]
    assert req("/admin/", cookie=ck)[2] == b"page-viewer" and req("/", cookie=ck)[1]["Location"] == "/admin/"
    assert req("/logout", cookie=ck)[0] == 404  # a GET (link, image) can't log anyone out
    assert req("/logout", "", ck)[0] == 303
    assert req("/admin/", cookie=ck)[0] == 302  # the old cookie is dead
    ck = req("/login", "user=bob&password=pw")[1]["Set-Cookie"].split(";")[0]
    user_del(conf, "bob", "viewer")
    os.utime(conf, (now + 10, now + 10))  # coarse file systems: make the change visible
    assert req("/admin/", cookie=ck)[0] == 302  # a login that was removed loses its sessions at once
    httpd.shutdown()
    httpd.server_close()
    print("netstats selftest: ok")
    return 0


# --- main ------------------------------------------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="SekurIRCd network stats panel", formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__.split("\n\n", 1)[1])
    ap.add_argument("command", nargs="?", choices=["serve", "render", "ingest", "geoip-update", "check", "selftest"])
    ap.add_argument("-c", "--config", default=os.path.join(HERE, "stats.toml"))
    ap.add_argument("--daemon", action="store_true", help="serve: run in the background")
    ap.add_argument("--pidfile", default=os.path.join(HERE, "netstats.pid"))
    ap.add_argument("--logfile", default=os.path.join(ROOT, "logs", "netstats.log"))
    ap.add_argument("--stop", action="store_true", help="stop a running --daemon")
    g = ap.add_argument_group("logins (edit [[users]] in stats.toml; a running panel picks the change up)")
    g.add_argument("--user", "-user", action="store_true", help="manage panel logins (with --admin/--viewer and --add/--del/--status)")
    r = g.add_mutually_exclusive_group()
    r.add_argument("--admin", "-admin", action="store_const", dest="role", const="admin", help="admin login: everything")
    r.add_argument("--viewer", "-viewer", action="store_const", dest="role", const="viewer", help="viewer login: no security data, no IPs")
    o = g.add_mutually_exclusive_group()
    o.add_argument("--add", "-add", metavar="NAME", help="add a login (asks for its password, or takes --hash)")
    o.add_argument("--del", "-del", metavar="NAME", dest="delete", help="remove a login")
    o.add_argument("--status", "-status", action="store_true", help="list the logins")
    g.add_argument("--hash", "-hash", metavar="HASH", help="with --add: a hash from --mkpasswd instead of asking")
    g.add_argument("--mkpasswd", "-mkpasswd", action="store_true", help="ask for a password and print its hash")
    a = ap.parse_args()
    try:
        if a.stop:
            return stop(a.pidfile)
        if a.mkpasswd:
            print(ask_password())
            return 0
        if a.user:
            if not (a.add or a.delete or a.status):
                ap.error("--user needs --add NAME, --del NAME or --status")
            if (a.add or a.delete) and not a.role:
                ap.error("say which kind: --admin or --viewer")
            c = load_config(a.config)
            if a.status:
                user_status(c, a.role)
            elif a.add:
                h = a.hash or ask_password()
                if not h.startswith("scrypt$"):
                    raise ConfigError("--hash takes what --mkpasswd prints (scrypt$...)")
                user_add(c["path"], a.add, a.role, h)
                print(f"netstats: added {a.role} login '{a.add}' to {c['path']}")
            else:
                user_del(c["path"], a.delete, a.role)
                print(f"netstats: removed {a.role} login '{a.delete}' from {c['path']}")
            return 0
        if a.command == "selftest":
            return selftest()
        if not a.command:
            ap.print_help()
            return 2
        c = load_config(a.config)
        if a.command == "check":
            if c["http"]["enabled"] and not c["users"] and not c["http"]["public"]:
                # exit 3: a valid file the panel still can't be served from (confcheck shows it as a warning)
                print("netstats: the panel has no logins and public = false, so nobody could open it -- "
                      "add one: netstats.py --user --admin --add NAME", file=sys.stderr)
                return 3
            print(f"netstats: configuration OK ({a.config})")
            for n in exposure_notes(c["http"]):
                print("netstats: " + n)
            return 0
        if a.command == "geoip-update":
            geoip_update(c)
            return 0
        if a.command == "ingest":
            print(f"netstats: {ingest(c)} records loaded into {c['db']}")
            return 0
        if a.command == "render":
            db = open_db(c)
            ingest(c, db)
            resolve_locations(c, db)
            run_probes(c, db)
            out = export(c, db)
            print("netstats: wrote " + (", ".join(out) if out else "nothing -- set [export] public_html / admin_html"))
            return 0
        if a.command == "serve":
            if not c["http"]["enabled"]:
                raise ConfigError("[http] enabled = false -- use 'render' from cron instead")
            if a.daemon:
                if pid_alive(a.pidfile):
                    print(f"netstats: already running (pid {pid_alive(a.pidfile)})", file=sys.stderr)
                    return 2
                for n in exposure_notes(c["http"]):  # before the fork, so ./sekurircd start-stats shows it
                    print("netstats: " + n, file=sys.stderr)
                daemonize(a.pidfile, a.logfile)
            Panel(c, log).serve()
    except ConfigError as e:
        print(f"netstats: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"netstats: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
