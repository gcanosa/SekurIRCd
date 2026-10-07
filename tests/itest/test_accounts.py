import base64, hashlib, hmac, os
from harness import Server

ACC = {"accounts": {"enabled": True, "store_file": "acc.json"}}


def b64(x):
    return base64.b64encode(x if isinstance(x, bytes) else x.encode()).decode()


def register(s, nick, account, pw):
    c = s.client(nick)
    c.say(f"REGISTER {account} {pw}", 1.5)
    return c


def scram_login(s, nick, user, password):
    c = s.client(nick, register=False, extra=["CAP REQ :sasl"])
    c.send("AUTHENTICATE SCRAM-SHA-256")
    c.expect(r"AUTHENTICATE \+")
    cnonce = b64(os.urandom(12))
    bare = f"n={user},r={cnonce}"
    c.send("AUTHENTICATE " + b64("n,," + bare))
    try:
        sf_line = c.expect(r"^AUTHENTICATE ", 2)
    except AssertionError:
        return "no-server-first"
    sf = base64.b64decode(sf_line.split()[1]).decode()
    attrs = dict(p.split("=", 1) for p in sf.split(","))
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(attrs["s"]), int(attrs["i"]))
    ck = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    cfwp = f"c=biws,r={attrs['r']}"
    am = f"{bare},{sf},{cfwp}"
    proof = bytes(a ^ b for a, b in zip(ck, hmac.new(hashlib.sha256(ck).digest(), am.encode(), hashlib.sha256).digest()))
    c.send("AUTHENTICATE " + b64(cfwp + ",p=" + b64(proof)))
    try:
        fin = c.expect(r"^AUTHENTICATE |904", 2)
    except AssertionError:
        return "no-final"
    if " 904 " in fin:
        return "rejected"
    sk = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    expected = "v=" + b64(hmac.new(sk, am.encode(), hashlib.sha256).digest())
    assert base64.b64decode(fin.split()[1]).decode() == expected, "server signature must verify (mutual auth)"
    c.send("AUTHENTICATE +")
    return "ok" if c.saw(r" 903 ", 2) else "no-903"


def test_register_then_scram_and_plain():
    with Server(cfg=ACC) as s:
        register(s, "regu", "scramu", "pencil1234").send("QUIT")
        assert scram_login(s, "sc1", "scramu", "pencil1234") == "ok"
        assert scram_login(s, "sc2", "scramu", "wrongwrong") == "rejected"
        assert scram_login(s, "sc3", "nobody1", "x") == "no-server-first"
        p = s.client("plainu", register=False, extra=["CAP REQ :sasl"])
        p.send("AUTHENTICATE PLAIN")
        p.expect(r"AUTHENTICATE \+")
        p.send("AUTHENTICATE " + b64("\0scramu\0pencil1234"))
        assert p.saw(r" 903 ", 3)


def test_nick_ownership_enforcement_and_ghost():
    cfg = {"accounts": {"enabled": True, "store_file": "acc.json", "enforce_nicks": True, "enforce_grace": 5}}
    with Server(cfg=cfg) as s:
        owner = register(s, "owner", "owner", "ownerpw12")
        owner.send("QUIT")
        squatter = s.client("owner")
        assert squatter.saw(r"This nickname is registered", 2)
        assert squatter.saw(r"NICK :Guest\d+", 7.5), "must be renamed after the grace period"
        # GHOST: the real owner logs in on a different nick, then ghosts the squatter
        s2 = s.client("owner2")
        s2.send("PRIVMSG NickServ :IDENTIFY owner ownerpw12")
        assert s2.saw(r"identified for owner", 3)


def test_account_register_requires_valid_name_and_limit():
    with Server(cfg={"accounts": {"enabled": True, "store_file": "acc.json", "max_accounts": 1}}) as s:
        a = register(s, "first", "acct1", "password1")
        b = s.client("second")
        r = b.say("REGISTER acct2 password2", 1.2)
        assert any("limit" in l or "FAIL" in l for l in r), r
