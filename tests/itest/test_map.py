"""/MAP: one aligned row per server with its users and share of the network; services bots are not users."""
import re
from harness import Network

CFG = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}], "accounts": {"enabled": True}}
ROW = re.compile(r"^(?P<text>.+?) -{2,} \| Users: +(?P<n>\d+) \( *(?P<pct>\d+\.\d\d)%\)$")


def rows(lines):
    out = []
    for l in lines:
        if " 006 " in l:
            out.append(l.split(" 006 ", 1)[1].split(" ", 1)[1].lstrip(":"))  # drop our nick
    return out


def test_map_shows_users_and_share_aligned():
    n = Network(cfg=CFG)  # services run next to the first server, and are always 0 (0.00%)
    n.add("a")
    n.add("b", parent="a")
    n.add("c", parent="b")
    with n:
        watcher = n.client("a", "watcher")
        bob1, bob2 = n.client("b", "bob1"), n.client("b", "bob2")  # kept: a dropped Client closes its socket
        carol = n.client("c", "carol")
        got = rows(watcher.say("MAP", 0.8))
        text = "\n".join(got)
        assert len(got) == 4, text  # a, b, c and the services link
        m = [ROW.match(r) for r in got]
        assert all(m), text
        # the "|" lines up on every row, whatever the depth of the row
        assert len({r.index(" | Users:") for r in got}) == 1, text
        by = {x["text"].lstrip("|` -"): x for x in m}
        assert by["a.test.net"]["n"] == "1" and by["b.test.net"]["n"] == "2" and by["c.test.net"]["n"] == "1", text
        # watcher + 2 + 1 = 4 real users; NickServ/ChanServ are not counted anywhere
        assert [by[k]["pct"] for k in ("a.test.net", "b.test.net", "c.test.net")] == ["25.00", "50.00", "25.00"], text
        assert by["services.test.net"]["n"] == "0" and by["services.test.net"]["pct"] == "0.00", text
        assert abs(sum(float(x["pct"]) for x in m) - 100.0) < 0.05, text
        # a chain a - b - c: the tree glyphs nest, and the services link is the last row
        assert got[0].startswith("a.test.net ") and got[1].startswith("|-b.test.net ") and got[2].startswith("| `-c.test.net "), text
        assert got[3].startswith("`-services.test.net "), text
