"""Integration-test harness: spawns real bin/sekurircd (and bin/chanserv) processes
on free localhost ports with a generated config, and gives tests a tiny IRC client.
Stdlib only. Everything lives in a temp directory that is removed afterwards."""
import os, re, shutil, signal, socket, subprocess, tempfile, time, base64, struct, hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
IRCD = os.path.join(ROOT, "bin", "sekurircd")
CHANSERV = os.path.join(ROOT, "bin", "chanserv")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def toml_value(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(toml_value(x) for x in v) + "]"
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_toml(cfg):
    """cfg: {section: {key: val}} for tables, {section: [ {..}, {..} ]} for arrays of tables."""
    out = []
    for sec, body in cfg.items():
        if isinstance(body, list):
            for tbl in body:
                out.append(f"[[{sec}]]")
                out += [f"{k} = {toml_value(v)}" for k, v in tbl.items()]
                out.append("")
        else:
            out.append(f"[{sec}]")
            out += [f"{k} = {toml_value(v)}" for k, v in body.items()]
            out.append("")
    return "\n".join(out)


class Server:
    """One ircd process. `cfg` entries override/extend the defaults (section-level merge)."""

    def __init__(self, name="irc.test.net", cfg=None, sid=None):
        self.name = name
        self.dir = tempfile.mkdtemp(prefix="itest-")
        self.port = free_port()
        self.tls_port = free_port()
        self.ws_port = free_port()
        self.link_port = free_port()
        self.cfg = {
            "server": {"name": name, "network": "TestNet", "bind": "127.0.0.1", "port": self.port},
            "logging": {"enabled": True, "directory": os.path.join(self.dir, "logs"), "level": "DEBUG"},
            "security": {"rdns_enabled": False, "ident_enabled": False, "flood_max_msgs": 1000, "connect_flood_max": 100000},
            "messages": {"motd": "none.motd"},
        }
        if sid:
            self.cfg["server"]["sid"] = sid
        for sec, body in (cfg or {}).items():
            if isinstance(body, list):
                self.cfg[sec] = body
            else:
                self.cfg.setdefault(sec, {}).update(body)
        self.proc = None

    def write_config(self):
        self.cfg_path = os.path.join(self.dir, "ircd.toml")
        with open(self.cfg_path, "w") as f:
            f.write(render_toml(self.cfg))

    def start(self):
        self.write_config()
        self.out = open(os.path.join(self.dir, "ircd.out"), "w")
        self.proc = subprocess.Popen([IRCD, "-c", self.cfg_path, "--pidfile", os.path.join(self.dir, "ircd.pid")],
                                     cwd=self.dir, stdout=self.out, stderr=subprocess.STDOUT)
        deadline = time.time() + 8
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("ircd exited early:\n" + self.output())
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.3).close()
                return self
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("ircd did not start:\n" + self.output())

    def output(self):
        try:
            self.out.flush()
            return open(os.path.join(self.dir, "ircd.out")).read()
        except OSError:
            return ""

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        shutil.rmtree(self.dir, ignore_errors=True)

    def restart(self):
        """Stop the process (SIGTERM, so it saves state) but keep the directory; start it again on the same ports."""
        self.proc.terminate()
        self.proc.wait(8)
        self.start()

    def reload(self):
        """Rewrite the config (after editing self.cfg) and send SIGHUP."""
        self.write_config()
        self.port = self.cfg["server"]["port"]
        self.proc.send_signal(signal.SIGHUP)
        time.sleep(0.6)

    def __enter__(self):
        return self.start()

    def __exit__(self, *a):
        self.stop()

    def client(self, nick, **kw):
        return Client(self.port, nick, **kw)


class Client:
    def __init__(self, port, nick, user=None, realname="Test User", caps=None, register=True, extra=(), host="127.0.0.1", sock=None):
        self.nick = nick
        self.sock = sock or socket.create_connection((host, port), timeout=3)
        self.sock.settimeout(0.2)
        self.buf = b""
        self.lines = []
        for l in extra:
            self.send(l)
        if caps:
            self.send("CAP LS 302")
            self.send("CAP REQ :" + " ".join(caps))
            self.send("CAP END")
        if register:
            self.send(f"NICK {nick}")
            self.send(f"USER {user or nick} 0 * :{realname}")
            self.expect(r" 001 ", 5)

    def send(self, line):
        self.sock.sendall((line + "\r\n").encode())

    def _fill(self, wait):
        end = time.time() + wait
        while True:
            try:
                d = self.sock.recv(65536)
                if not d:
                    return False
                self.buf += d
            except socket.timeout:
                if time.time() >= end:
                    return True
                continue
            except OSError:
                return False
            if b"\n" in self.buf:
                break
        return True

    def _split(self):
        while b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            self.lines.append(line.rstrip(b"\r").decode(errors="replace"))

    def drain(self, wait=0.3):
        """Read whatever arrives within `wait` seconds; returns and clears all pending lines."""
        end = time.time() + wait
        while time.time() < end:
            if not self._fill(0.05):
                break
            self._split()
        self._split()
        out, self.lines = self.lines, []
        return out

    def expect(self, pattern, timeout=3):
        """Waits for a line matching the regex; returns it (earlier lines stay buffered for later expects)."""
        rx = re.compile(pattern)
        end = time.time() + timeout
        while True:
            for i, l in enumerate(self.lines):
                if rx.search(l):
                    del self.lines[:i + 1]
                    return l
            if time.time() >= end:
                raise AssertionError(f"{self.nick}: no line matching {pattern!r}; buffered: {self.lines[-8:]}")
            self._fill(0.1)
            self._split()

    def saw(self, pattern, wait=0.4):
        """True if a matching line arrives within `wait` (consumes up to and including it)."""
        try:
            self.expect(pattern, wait)
            return True
        except AssertionError:
            return False

    def say(self, line, wait=0.3):
        self.send(line)
        return self.drain(wait)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def ws_frame(payload, opcode=1):
    b = payload.encode() if isinstance(payload, str) else payload
    mask = os.urandom(4)
    n = len(b)
    hdr = bytes([0x80 | opcode])
    if n < 126:
        hdr += bytes([0x80 | n])
    else:
        hdr += bytes([0x80 | 126]) + struct.pack(">H", n)
    return hdr + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(b))


def ws_parse(buf):
    """Returns ([(opcode, text)], remaining_bytes) from a server->client byte stream."""
    out = []
    while len(buf) >= 2:
        ln, h = buf[1] & 0x7F, 2
        if ln == 126:
            if len(buf) < 4:
                break
            ln, h = struct.unpack(">H", buf[2:4])[0], 4
        if len(buf) < h + ln:
            break
        out.append((buf[0] & 0xF, buf[h:h + ln].decode(errors="replace")))
        buf = buf[h + ln:]
    return out, buf


class ChanServ:
    def __init__(self, srv, link_port, peer_name="services.test.net", password="svcsecret", extra=""):
        self.dir = tempfile.mkdtemp(prefix="itest-cs-")
        self.pidfile = os.path.join(self.dir, "cs.pid")
        with open(os.path.join(self.dir, "services.toml"), "w") as f:
            f.write(f'[link]\nhost = "127.0.0.1"\nport = {link_port}\nname = "{peer_name}"\npassword = "{password}"\n'
                    f'[chanserv]\nnick = "ChanServ"\n{extra}\n[storage]\npath = "cs.json"\nbackup_count = 1\n')
        self.proc = None

    def start(self):
        self.proc = subprocess.Popen([CHANSERV, "-c", "services.toml"], cwd=self.dir,
                                     stdout=open(os.path.join(self.dir, "out"), "w"), stderr=subprocess.STDOUT)
        time.sleep(1.2)
        return self

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self):
        return self.start()

    def __exit__(self, *a):
        self.stop()
