"""The services daemon's link to the hub over TLS ([link] tls = true in services.toml): what lets services run on another
machine than the hub. The hub's certificate is pinned by fingerprint or verified (ca_file / system CAs, and the name),
the check comes BEFORE the link password is sent, and the daemon can present a client certificate for the hub to pin.
A plain link keeps working exactly as before (loopback, or from another address when the hub's link port is not TLS), with a
warning on both sides."""
import os, socket, subprocess, tempfile, time
from harness import Server, Client, Services, SVC_NAME, SVC_PW, SERVICES
from test_conn import make_cert
from test_linktls import fp_of

OPERS = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}


def hub(tls=True, bind="127.0.0.1", peer_extra=None):
    """A hub whose link port speaks TLS (or not) and that expects the services daemon as a peer. -> (hub, crt, key)."""
    crt, key = make_cert(tempfile.mkdtemp(prefix="itest-lcert-"))
    h = Server("hub.test.net", cfg=dict(OPERS), sid="1HB")
    h.cfg["tls"] = {"enabled": True, "port": h.tls_port, "cert_file": crt, "key_file": key}
    h.cfg["links"] = {"enabled": True, "mode": "hub", "bind": bind, "port": h.link_port, "tls": tls}
    h.cfg["links.peers"] = [dict({"name": SVC_NAME, "password": SVC_PW}, **(peer_extra or {}))]
    h.auto_services = False
    h.start()
    return h, crt, key


def nickserv_up(h, wait=6):
    deadline = time.time() + wait
    while time.time() < deadline:
        probe = Client(h.port, f"w{int(time.time() * 1000) % 100000}")
        up = any(" 311 " in l for l in probe.say("WHOIS NickServ", 0.3))
        probe.send("QUIT"); probe.close()
        if up:
            return True
        time.sleep(0.3)
    return False


def run(h, link_extra, host="127.0.0.1", wait=6):
    """Start services against `h`; -> (linked?, services output)."""
    svc = Services(h, h.link_port, link_extra=link_extra, host=host)
    svc.start()
    try:
        ok = nickserv_up(h, wait)
        return ok, svc.output()
    finally:
        svc.stop()


def test_pinned_hub_certificate():
    h, crt, _ = hub()
    try:
        ok, out = run(h, f'tls = true\nfingerprint = "{fp_of(crt)}"\n')
        assert ok, out + h.output()[-1500:]
        assert "TLS established" in out and "certificate pinned" in out, out
        assert "TLS handshake complete for inbound link" in h.output()
    finally:
        h.stop()


def test_wrong_pin_never_sends_the_password():
    h, _, _ = hub()
    try:
        ok, out = run(h, 'tls = true\nfingerprint = "sha256:' + "0" * 64 + '"\n', wait=3)
        assert not ok and "not the pinned sha256:" + "0" * 64 in out, out
        assert f"link '{SVC_NAME}' authenticated" not in h.output(), "the hub saw a PASS: the password went to a server that wasn't pinned"
    finally:
        h.stop()


def test_certificate_verified_by_ca_and_name():
    h, crt, _ = hub()
    try:  # CN=localhost: the self-signed certificate is its own CA, and the name in [link] host must match it
        ok, out = run(h, f'tls = true\nca_file = "{crt}"\n', host="localhost")
        assert ok and "certificate verified" in out, out + h.output()[-800:]
    finally:
        h.stop()


def test_unverifiable_certificate_is_refused():
    h, crt, _ = hub()
    try:
        ok, out = run(h, "tls = true\n", wait=3)  # no pin, no ca_file: a self-signed certificate is nobody's
        assert not ok and "TLS handshake to" in out and "failed" in out, out
        assert f"link '{SVC_NAME}' authenticated" not in h.output()
        ok, out = run(h, f'tls = true\nca_file = "{crt}"\n', wait=3)  # trusted, but 127.0.0.1 is not the name on it
        assert not ok and "failed" in out, out
    finally:
        h.stop()


def test_client_certificate_pinned_by_the_hub():
    scrt, skey = make_cert(tempfile.mkdtemp(prefix="itest-lcert-"))
    h, crt, _ = hub(peer_extra={"fingerprint": fp_of(scrt)})
    try:
        link = f'tls = true\nfingerprint = "{fp_of(crt)}"\ncert = "{scrt}"\nkey = "{skey}"\n'
        ok, out = run(h, link)
        assert ok, out + h.output()[-1500:]
        ok, out = run(h, f'tls = true\nfingerprint = "{fp_of(crt)}"\n', wait=3)  # no certificate for a pinned peer
        assert not ok, "the hub pins this daemon: a link without its certificate is refused"
    finally:
        h.stop()
    h, crt, _ = hub(peer_extra={"fingerprint": "sha256:" + "1" * 64})  # pinned to some other certificate
    try:
        ok, out = run(h, f'tls = true\nfingerprint = "{fp_of(crt)}"\ncert = "{scrt}"\nkey = "{skey}"\n', wait=3)
        assert not ok, "a certificate that isn't the pinned one is refused"
    finally:
        h.stop()


def test_bad_tls_settings_stop_services_at_start():
    d = tempfile.mkdtemp(prefix="itest-svc-")
    for body, want in (('tls = false\nfingerprint = "sha256:' + "a" * 64 + '"\n', "do nothing without tls = true"),
                       ('tls = true\ncert = "c.pem"\n', "cert and key go together"),
                       ('tls = true\nfingerprint = "nothex"\n', "must be the hub certificate's SHA-256")):
        conf = os.path.join(d, "services.toml")
        with open(conf, "w") as f:
            f.write(f'[link]\nhost = "127.0.0.1"\nport = 1\nname = "{SVC_NAME}"\npassword = "{SVC_PW}"\n{body}\n[storage]\npath = "cs.json"\n')
        r = subprocess.run([SERVICES, "-c", conf], cwd=d, capture_output=True, text=True, timeout=10)
        assert r.returncode != 0 and want in r.stdout + r.stderr, (want, r.stdout, r.stderr)


def lan_ip():
    """This machine's address on the network (not loopback), or None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # a UDP "connect" only picks a route: nothing is sent
        ip = s.getsockname()[0]
        return None if ip.startswith("127.") else ip
    except OSError:
        return None
    finally:
        s.close()


def test_services_from_another_address():
    """The real remote case: the hub sees the daemon at a non-loopback address. Plain text still links when the hub's link
    port is plain (and both sides warn); a TLS hub takes it only over TLS."""
    ip = lan_ip()
    if not ip:
        print("    (no non-loopback address on this machine: skipped)")
        return
    h, crt, _ = hub(tls=False, bind="0.0.0.0")
    try:
        ok, out = run(h, "", host=ip)
        assert ok, "a plain link from another address keeps working when the hub's link port is plain\n" + out + h.output()[-800:]
        assert "plain text" in out and "unencrypted" in out, ("the daemon warns", out)
        assert "is plain text: IDENTIFY and SASL passwords" in h.output(), "and so does the hub"
    finally:
        h.stop()
    h, crt, _ = hub(tls=True, bind="0.0.0.0")
    try:
        ok, out = run(h, "", host=ip, wait=3)
        assert not ok, "a TLS hub takes plain text from loopback only"
        ok, out = run(h, f'tls = true\nfingerprint = "{fp_of(crt)}"\n', host=ip)
        assert ok, "over TLS it links from another address\n" + out + h.output()[-800:]
        assert "is plain text: IDENTIFY" not in h.output()
    finally:
        h.stop()


def test_require_tls_refuses_plain_text_to_another_machine():
    """[link] require_tls = true: TLS or nothing for a hub on another machine. A hub on this machine is not "another machine",
    so a plain loopback link is unaffected; and with TLS on it changes nothing."""
    h, crt, _ = hub(tls=False)
    try:
        ok, out = run(h, "require_tls = true\n")
        assert ok, "a plain link to this machine still works\n" + out + h.output()[-800:]
    finally:
        h.stop()
    ip = lan_ip()
    if not ip:
        print("    (no non-loopback address on this machine: the rest skipped)")
        return
    h, crt, _ = hub(tls=False, bind="0.0.0.0")
    try:
        ok, out = run(h, "require_tls = true\n", host=ip, wait=3)
        assert not ok and "require_tls is on" in out, out
        # it has to connect to learn where the hub is, but the credentials are right: a link that never authenticated never got a PASS
        assert f"link '{SVC_NAME}' authenticated" not in h.output(), "no password may be sent in plain text"
    finally:
        h.stop()
    h, crt, _ = hub(tls=True, bind="0.0.0.0")
    try:
        ok, out = run(h, f'tls = true\nfingerprint = "{fp_of(crt)}"\nrequire_tls = true\n', host=ip)
        assert ok, "require_tls does not get in the way of TLS\n" + out + h.output()[-800:]
    finally:
        h.stop()
