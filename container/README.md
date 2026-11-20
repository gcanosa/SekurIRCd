# SekurIRCd in a container

Run the ircd, services (NickServ + ChanServ) and the stats panel from one image, with podman or Docker, on x86-64 or arm64
(servers, a Raspberry Pi 3/4/5 on a 64-bit OS). The image holds only code and templates; **everything you own lives in one
directory on the host**, so you can rebuild, upgrade or delete the containers without losing your config, accounts or bans.

| You want | Use |
|---|---|
| podman 5.0+ on a systemd Linux (Ubuntu 26.04, Debian 13, Fedora, Raspberry Pi OS based on Debian 13) | [`setup.sh`](#quick-start-with-setupsh): guided, starts at boot |
| the same by hand, to see every step | [Step by step](#step-by-step-by-hand) |
| Docker, older podman, or no systemd user session | [Compose](#docker-and-compose) |

32-bit ARM (armv7, e.g. Raspberry Pi OS 32-bit) is not supported: there is no image for it. Use a 64-bit OS.

## Quick start with `setup.sh`

```sh
git clone https://github.com/gcanosa/SekurIRCd.git && cd SekurIRCd
container/setup.sh install
```

`setup.sh` is a single file; you can also download just that file (it carries its own unit files). It:

1. **checks the machine**: podman 5.0+, a systemd user session, x86-64 or arm64, and that you are not root (the containers are rootless);
2. **pulls the image** (`ghcr.io/gcanosa/sekurircd:latest`; `--image …:edge` for the newest, or `--build` to build from this checkout);
3. asks **where to keep your data** (default `~/sekurircd`) and creates it;
4. runs the **config wizard** in the container: a few questions, then it writes `sekurircd.toml`, `services.toml`, the
   Protection bundle, a self-signed TLS certificate and optionally the stats panel, and checks all of them before saving;
5. installs three **systemd user units** (Quadlet) in `~/.config/containers/systemd/` and starts them;
6. turns on **linger** (`loginctl enable-linger`), so it starts at boot and keeps running when you log out;
7. checks the ircd answers on its port and prints what to do next (firewall, connecting, `/OPER`).

Then, day to day:

```sh
container/setup.sh status                  # what runs, which version
container/setup.sh logs [ircd|services|stats]
container/setup.sh rehash                  # re-read the config (what /REHASH does); also after a certificate renewal
container/setup.sh restart [ircd|services|stats]    # start | stop work the same way
container/setup.sh wizard                  # run the questions again (the old files are backed up first)
container/setup.sh hash-password           # an oper or services password hash for a config you edit by hand
container/setup.sh backup                  # a tar.gz of config/, services/, stats/ (it holds secrets: keep it private)
container/setup.sh upgrade                 # pull the new image, restart services and the panel, ask before the ircd
container/setup.sh uninstall               # remove the units (your data stays)
```

`SEKURIRCD_DATA` and `SEKURIRCD_IMAGE` set the defaults; `install --data DIR --image IMAGE` overrides them.

## Where everything lives

`~/sekurircd` (or your directory) is mounted at `/data` in every container and laid out like the repository root:

| Path | What |
|---|---|
| `config/sekurircd.toml` | the ircd's config; `protection.toml` next to it (DNSBL, limits, proxy scanner) |
| `config/tls/cert.pem`, `key.pem` | the TLS certificate and key (the wizard makes a self-signed one) |
| `config/accounts.json`, `klines.json`, `alwayson.json`, `history.json` | accounts, bans, always-on sessions, channel history: **back these up** |
| `config/ircd.motd`, `oper.motd`, `ircd.rules`, `spamfilters.conf` | yours to edit; made from the `*.template.*` files the first time |
| `config/*.template.*` | the image's templates, refreshed at every start: read them for the options, never edit them |
| `services/services.toml`, `nickserv.json`, `chanserv.json` | services config and the accounts and registered channels |
| `stats/stats.toml`, `stats.db`, `events.log` | the stats panel (only when you turned it on) |
| `logs/` | the ircd's log files; the daemons also log to the container, so `logs` / `journalctl` show them too |

Edit a config file on the host, then `container/setup.sh rehash`. Only `[server] name` and `sid` need a restart.

## Step by step, by hand

What `setup.sh` does, with plain commands: use this to understand it, or on a machine where you can't run the script.

```sh
# 1. The image, and a directory for your data.
podman pull ghcr.io/gcanosa/sekurircd:latest
mkdir -p ~/sekurircd

# 2. Options every container shares. keep-id makes the container run as you, so the files in ~/sekurircd are yours;
#    :z lets all three containers read it; --network host is explained under "Networking".
IMG=ghcr.io/gcanosa/sekurircd:latest
OPTS="--network host --userns=keep-id:uid=1000,gid=1000 -v $HOME/sekurircd:/data:z --read-only --cap-drop ALL --security-opt no-new-privileges"

# 3. The initial config: the wizard asks, writes and checks it (it needs a terminal: -it).
podman run -it --rm $OPTS $IMG makeconf
podman run --rm $OPTS $IMG sekurircd --config /data/config/sekurircd.toml --check     # the same check the wizard ran

# 4. Run the ircd, then services, then the stats panel (only if you made a stats.toml).
podman run -d --name sekurircd-ircd      --restart on-failure $OPTS $IMG ircd
podman run -d --name sekurircd-services  --restart on-failure $OPTS $IMG services
podman run -d --name sekurircd-stats     --restart on-failure $OPTS $IMG stats

# 5. Day to day
podman logs -f sekurircd-ircd
podman kill --signal HUP sekurircd-ircd          # rehash
podman stop sekurircd-ircd                       # a graceful stop
```

The image's entrypoint takes one of `ircd`, `services`, `stats`, `makeconf`, or any command (`sekurircd --version`,
`sekurircd --hash-password`, `sh`). To start at boot, put each `podman run` in a systemd user unit; `setup.sh` writes them for you.

## Networking

The containers use the **host network** (`--network host`). That is deliberate: the ircd decides everything by the client's
address (K-lines and Z-lines, per-IP limits, cloaks, DNSBL, flood protection), and a NATed container network shows every
client as the gateway. It also means there is nothing to publish: the ircd listens on exactly the ports in `sekurircd.toml`.

* **Open the firewall** for the client port (6667) and the TLS port (6697), plus the WebSocket port if you use it.
* The **link port** (7000) listens on `127.0.0.1` unless you said "link to other servers": services reach it over the host's
  loopback. Open it only to the servers you link, and set `allowed_ips`.
* The stats panel listens on `127.0.0.1:8089` by default. Put a reverse proxy in front of it (the wizard prints a Caddy block), or
  bind it publicly with its own TLS certificate.
* Ports below 1024 need `sysctl net.ipv4.ip_unprivileged_port_start=…` for rootless podman; the defaults don't.
* **Check real addresses once:** connect from *another* machine and `/WHOIS` yourself. It must show that machine's address.

If you prefer a published-port network instead, you take on that check yourself (podman 5's default `pasta` forwards the
source address; a bridge or slirp network may not).

## TLS certificates

The wizard makes a self-signed certificate. For a real one, put the files in `config/tls/` (the names in `[tls]`), then
`container/setup.sh rehash`. With Let's Encrypt, point your renewal hook at the same two commands:
copy the new `fullchain.pem` and `privkey.pem` into `~/sekurircd/config/tls/`, then `podman kill --signal HUP sekurircd-ircd`
(the key must be readable by your user, mode 0600).

## Upgrading, backups, moving

* **Upgrade:** `container/setup.sh upgrade`. Services and the panel restart at once without disconnecting anyone; restarting the
  ircd drops its clients (always-on sessions come back), so it asks first. To roll back, set `Image=` to a release tag
  (`…/sekurircd:1.3.4`) in `~/.config/containers/systemd/sekurircd-*.container`, then
  `systemctl --user daemon-reload && container/setup.sh restart`.
* **Tags:** `latest` is the newest release, `1.3.4` / `1.3` pin one, `edge` is the newest commit on `main` (every platform's CI was green).
  Updates are never automatic: an IRC server restart is your call.
* **Backup:** `container/setup.sh backup` (a tar.gz of `config/`, `services/` and `stats/`; keep it private, it holds password hashes and your TLS key).
* **Moving to another machine:** install there, stop, copy the data directory over, start. The SID and cloak secret travel with it.

## Docker and Compose

[`compose.yaml`](compose.yaml) in this directory runs the same three containers (services and stats are Compose *profiles*).
Its header lists the commands. It needs Docker Compose v2 or `podman compose`, and a Linux host (host networking).

## Raspberry Pi

A Pi 3, 4 or 5 on a 64-bit OS (Raspberry Pi OS 64-bit, Ubuntu) pulls the arm64 image: no compiling on the Pi. Keep `~/sekurircd` on a good SD card or a USB
disk: the logs and the JSON files are written all day.

## Build the image yourself

```sh
container/build.sh                       # sekurircd:local, from this checkout, with podman (ENGINE=docker for docker)
container/smoke.sh sekurircd:local       # the end-to-end check CI runs: wizard, ircd + services + panel, restart, rehash, stop
container/setup.sh install --build       # build and install in one go
```

CI builds the image natively on x86-64 and arm64, runs `smoke.sh` on both, and publishes it to `ghcr.io/gcanosa/sekurircd`
only after every platform's tests pass: `edge` from `main`, `latest` and the version tags from a `v*` tag.

## Troubleshooting

* **`Permission denied` on `/data`:** the container must run as your user: `--userns=keep-id:uid=1000,gid=1000` (podman) or
  `--user $(id -u):$(id -g)` (Docker). Without it a rootless container can't write to your directory.
* **A container can't read the config after another started (SELinux):** the volume needs `:z` (shared label), not `:Z`.
  `setup.sh` and `compose.yaml` use `:z`.
* **`setup.sh` says no systemd user session:** log in with a full session (ssh, console), not `su`/`sudo -u`, or use Compose.
* **It stops when you log out:** linger is off: `sudo loginctl enable-linger $USER`.
* **`could not pull`:** check the image name and that the package is public; a checkout can always `install --build`.
* **Logs:** `container/setup.sh logs ircd`, or `journalctl --user -u sekurircd-ircd -f`; files are in `~/sekurircd/logs/`.
* **Where's the pidfile / `./sekurircd start`?** Not used: the daemons run in the foreground and the container runtime supervises them.
