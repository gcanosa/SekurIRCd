"""--daemon: the command returns only once the daemon's pidfile exists (a Type=forking systemd unit and the ./sekurircd
wrapper read it the moment the command returns), for the ircd and for services."""
import os, subprocess, tempfile, time
from harness import Server, IRCD, SERVICES, free_port


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def stopped(binary, pidfile):
    subprocess.run([binary, "--stop", "--pidfile", pidfile], capture_output=True, timeout=20)


def test_the_ircd_returns_only_once_its_pidfile_exists():
    s = Server()
    s.write_config()
    pf = os.path.join(s.dir, "daemon.pid")
    for _ in range(5):  # the race this closes was a matter of milliseconds: several starts, each checked the instant it returns
        p = subprocess.run([IRCD, "-c", s.cfg_path, "--daemon", "--pidfile", pf], cwd=s.dir, capture_output=True, text=True, timeout=30)
        try:
            assert p.returncode == 0, p.stderr
            pid = int(open(pf).read())  # no sleep, no retry: it is there now
            assert alive(pid)
        finally:
            stopped(IRCD, pf)
        assert not os.path.exists(pf), "removed again on a stop"
        time.sleep(0.3)


def test_services_return_only_once_their_pidfile_exists():
    d = tempfile.mkdtemp(prefix="itest-daemon-")
    conf = os.path.join(d, "services.toml")
    with open(conf, "w") as f:  # a hub that isn't there: the daemon starts and keeps trying
        f.write(f'[link]\nhost = "127.0.0.1"\nport = {free_port()}\nname = "services.test.net"\npassword = "pw12345"\n'
                '[storage]\npath = "chanserv.json"\n')
    pf = os.path.join(d, "services.pid")
    for _ in range(5):
        p = subprocess.run([SERVICES, "-c", conf, "--daemon", "--pidfile", pf], cwd=d, capture_output=True, text=True, timeout=30)
        try:
            assert p.returncode == 0, p.stderr
            pid = int(open(pf).read())
            assert alive(pid)
        finally:
            stopped(SERVICES, pf)
        time.sleep(0.3)


def test_a_daemon_that_dies_while_starting_makes_the_command_fail():
    """Services with a corrupt accounts file refuse to start after they have daemonized: the command used to return 0 and
    leave nothing running; now it returns non-zero (a systemd unit reports the failed start, and the wrapper can too)."""
    d = tempfile.mkdtemp(prefix="itest-daemonfail-")
    conf = os.path.join(d, "services.toml")
    with open(os.path.join(d, "bad.json"), "w") as f:
        f.write("{{{ not json")
    with open(conf, "w") as f:
        f.write(f'[link]\nhost = "127.0.0.1"\nport = {free_port()}\nname = "services.test.net"\npassword = "pw12345"\n'
                '[nickserv]\nstore_file = "bad.json"\n[storage]\npath = "chanserv.json"\n')
    pf = os.path.join(d, "services.pid")
    p = subprocess.run([SERVICES, "-c", conf, "--daemon", "--pidfile", pf], cwd=d, capture_output=True, text=True, timeout=30)
    assert p.returncode != 0, "a start that failed must not look like a success"
    assert not os.path.exists(pf), "and leaves no pidfile behind"
