"""TLS server links with pinned certificate fingerprints ([[links.peers]] fingerprint)."""
import hashlib, os, ssl, tempfile, time
from harness import Network
from test_conn import make_cert


def fp_of(crt):
    return "sha256:" + hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(crt).read())).hexdigest()


def tls_net(pins=None, passwords=True, accounts=False):
    """hub + leaf, links over TLS, each with its own self-signed cert. pins(hub_fp, leaf_fp) -> (pin on the hub for the
    leaf, pin on the leaf for the hub); None = no pin. Returns (net, hub_fp, leaf_fp)."""
    net = Network(cfg={"accounts": {"enabled": True}} if accounts else None)
    hub, leaf = net.add("hub"), net.add("leaf", parent="hub")
    fps = {}
    for s in (hub, leaf):
        crt, key = make_cert(tempfile.mkdtemp(prefix="itest-lcert-"))
        s.cfg["tls"] = {"enabled": True, "port": s.tls_port, "cert_file": crt, "key_file": key}
        s.cfg["links"]["tls"] = True
        fps[s] = fp_of(crt)
    on_hub, on_leaf = (pins or (lambda h, l: (l, h)))(fps[hub], fps[leaf])
    hub_peer = next(p for p in hub.cfg["links.peers"] if p["name"] == leaf.name)
    leaf_peer = leaf.cfg["links.peers"][0]
    for peer, pin in ((hub_peer, on_hub), (leaf_peer, on_leaf)):
        if pin: peer["fingerprint"] = pin
        if not passwords: peer.pop("password")
    return net, fps[hub], fps[leaf]


def test_fingerprint_only_link_with_services_on_loopback():
    net, _, _ = tls_net(passwords=False, accounts=True)  # services link in plain text over 127.0.0.1 to a TLS listener
    with net:
        c = net.client("leaf", "fpuser")
        assert any(" 311 " in l for l in c.say("WHOIS NickServ", 0.5)), "services not reachable across the TLS link"
        assert "presented" not in net["hub"].output() and "is plain text -- allowed from loopback" in net["hub"].output()


def test_password_and_fingerprint_link():
    with tls_net()[0] as net:
        assert "(TLS)" in net["leaf"].output()


def test_wrong_pin_on_the_leaf_never_sends_the_password():
    net, _, _ = tls_net(pins=lambda _h, l: (l, "sha256:" + "0" * 64))
    net.start(wait=False)
    try:
        time.sleep(2.5)
        assert "not the pinned sha256:" + "0" * 64 in net["leaf"].output()
        assert "Link with" not in net["hub"].output() and "rejected link handshake" not in net["hub"].output()
    finally:
        net.stop()


def test_wrong_pin_on_the_hub_refuses_the_leaf():
    net, _, _ = tls_net(pins=lambda h, _l: ("sha256:" + "1" * 64, h))
    net.start(wait=False)
    try:
        time.sleep(2.5)
        out = net["hub"].output()
        assert "not the pinned sha256:" + "1" * 64 in out and "rejected link handshake" in out, out[-1500:]
    finally:
        net.stop()


def test_fingerprint_needs_link_tls():
    import subprocess
    from harness import IRCD, render_toml
    d = tempfile.mkdtemp(prefix="itest-fpcfg-")
    cfg = os.path.join(d, "c.toml")
    open(cfg, "w").write(render_toml({"server": {"name": "a.test.net"}, "links": {"enabled": True, "mode": "hub"},
                                      "links.peers": [{"name": "b.test.net", "fingerprint": "sha256:" + "a" * 64}]}))
    r = subprocess.run([IRCD, "--check", "-c", cfg], capture_output=True, text=True)
    assert r.returncode and "needs [links] tls = true" in r.stdout + r.stderr, r.stdout + r.stderr
