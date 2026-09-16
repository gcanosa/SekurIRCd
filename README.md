# SekurIRCd

A lightweight, **secure** IRC daemon written in **C11**, with no runtime
dependencies beyond OpenSSL and a small set of vendored single-file
libraries (TOML/JSON parsing, hash tables/lists).

Compatible with the standard IRC client protocol (RFC 1459/2812/2813 +
IRCv3 capability negotiation), so it works with **weechat, irssi, xchat,
BitchX**, **The Lounge**, and web clients such as **Kiwi** (which connect
over a gateway).

## Features (v1.0.2)

- Client connect + full registration (NICK/USER, CAP negotiation, welcome + MOTD)
- Channels: `JOIN` / `PART` / `NAMES` / `TOPIC` / `KICK` / `INVITE` / `LIST`
  (create-on-join; the creator is auto-opped; `[channels] restrict_creation`
  can lock new-channel creation to IRC operators, with an
  `allowed_channels` whitelist anyone may still create; `default_modes`
  (e.g. `"nt"`) is applied automatically to a newly created channel only)
- Channel modes via `MODE`: `+n/+i/+p/+t/+s/+m/+k/+l/+z`, prefix modes
  `+o`/`+h`/`+v` (`@`/`%`/`+`), and mask lists `+b` (ban) / `+e` (ban
  exception) / `+I` (invite-only exception, INVEX) -- all enforced on
  JOIN/PRIVMSG/TOPIC/NAMES/LIST/WHOIS (`+p`/`+s` hide a channel's name,
  topic, and membership from anyone not already in it; `+z` restricts JOIN to
  clients connected over TLS). `+r` (registered-with-services) is also a
  real mode, but services-only: no local client can set/clear it via
  `/MODE`, op or server oper alike -- `services/chanserv` sets/clears it
  on `REGISTER`/`DROP` over the trusted link protocol, so `/MODE #chan`
  reliably shows whether a channel is actually registered
- User modes via `MODE`: self-togglable `+i` (invisible -- hidden from
  `GLOB` unless you share a channel or the searcher's an oper), `+w`
  (WALLOPS), `+d` (drop CTCP sent to you), plus `+o` (operator, granted by
  `/OPER`, which also grants `+s` and `+w`), and `+Z` (connected over TLS --
  set by the server, not self-togglable); `[security] default_user_modes` (e.g.
  `"iw"`) applies self-togglable modes automatically once a client
  registers -- `+o`/`+Z` can never be granted this way
- TLS/SSL listener (`[tls]`): opt-in, runs alongside the plaintext listener
  on its own port (default `6697`, the conventional "ircs" port); a
  self-signed certificate is fine (still encrypted) -- clients just need
  "only allow trusted certificates" unchecked to connect to one. `WHOIS` on
  a TLS-connected user shows `671` ("is using a secure connection")
- `OPER` (server operators, configured in `[[operators]]` -- multiple opers
  supported, each with its own required `hosts` ident@host/IP mask list, e.g.
  `*@*` for anywhere or a specific mask to restrict a login to certain
  hosts/IPs), oper-only `KILL`, `WALLOPS` (delivered to `+w` users), and
  `REHASH`. Passwords are `password_hash` (scrypt, generated with
  `sekurircd --hash-password` -- recommended, so the config file holds no
  recoverable plaintext) or legacy plain-text `password`; exactly one is
  required per `[[operators]]` entry
- `SILENCE` (per-client ignore masks for private messages)
- `GLOB` -- a custom (non-RFC) server-wide glob nick search
- `USERHOST`, `ISON`, `LUSERS` (251-255/265/266, plus `250` peak-connections
  -- standard ircd wording, e.g. `There are N users and M invisible on 1
  servers`), `WHOWAS`, `ADMIN` (configured in `[admin]`), `STATS` (`m`/`u`/`o`)
- Host cloaking (`[security] host_masking`): masks every client's real
  IP/host behind a random `<token>.users.<network>` cloak; `/VHOST` lets a
  client switch to a named vhost from `[[vhosts]]` instead, if their real
  ident/IP matches that vhost's `allowed_hosts` (never matched by nick --
  opers may use any configured vhost regardless); `/CHGHOST <nick>
  <new-host>` lets a server operator force-set anyone's displayed host
  directly, no `[[vhosts]]` entry needed, and `/SETHOST <host>|off` is the
  same trick on your own connection. The real address stays visible to an
  oper or to the user themselves via `WHOIS` (378), never to anyone else.
- Oper overrides: `/SAJOIN <nick> <#chan>[,...]` and `/SAPART <nick>
  <#chan>[,...] [reason]` force a local user into or out of channels
  bypassing every normal gate (`+i`/`+k`/`+l`/`+b`/`+z`, ops); `/SAMODE
  <#chan> <modestring> [args...]` forces a channel-mode change without
  needing membership or ops first (still refuses `+r`, services-only).
- IRCv3 capabilities: `away-notify` (live `AWAY` updates for channel-mates
  who request it), `multi-prefix` (all rank prefixes in `NAMES`/`WHO`, not
  just the highest), `userhost-in-names` (full `nick!user@host` in
  `NAMES`/`JOIN`), `setname` (`SETNAME` changes realname live, broadcast to
  channel-mates who negotiated the cap), `chghost`, `extended-join`,
  `echo-message`, `message-tags`/`server-time`/`account-tag`,
  `account-notify`, `invite-notify`, `standard-replies`, and `sasl` (see
  Accounts below)
- Self-service accounts (`[accounts]`, off by default) + SASL PLAIN
  (`AUTHENTICATE`) and `/REGISTER <account> <password>` -- backs `330
  RPL_WHOISACCOUNT` and `EXTBAN=,a` (`+b`/`+e`/`+I` masks like `a:<account>`,
  matching by SASL account instead of hostmask). A small standalone store in
  core, independent of channel services below
- `TRACE`, `SERVLIST`/`SQUERY` (services pseudo-users, e.g. ChanServ, flag
  themselves for these), and `WHOX` (`WHO <mask> %<fields>,<token>` for
  custom field selection)
- Ident (RFC 1413, off by default) and reverse-DNS (on by default) lookups
  on connect, both best-effort with a configurable timeout
  (`[security] ident_enabled`/`rdns_enabled`), run on a worker-thread pool
  so a slow lookup never blocks the event loop
- `MONITOR` (IRCv3 efficient online/offline watch list, `+`/`-`/`C`/`L`/`S`
  subcommands, capped at 100 entries/client) -- the modern alternative to
  polling `ISON`
- `KNOCK` (request an invite on a `+i`/`+k` channel; delivered to channel
  ops), `LINKS`, `MAP`, `HELP`
- `KLINE`/`GLINE`/`UNKLINE`/`UNGLINE` (oper-only, IP masks, optional
  duration like `1d`/`12h`/`30m` -- permanent if omitted) -- disconnects
  matching connected clients and refuses future ones; persisted to
  `[security] klines_file` if set, so lines survive `/REHASH` and a restart
- DNSBL checking (`[dnsbl]`): reject/auto-K-line connections from IPs listed
  by a configured DNS blackhole-list provider (standard reversed-octet
  lookup, works with any provider's zone -- Spamhaus, SORBS, etc.); auto-lines
  default to a 1-day expiry (`kline_duration`) and can include a human-facing
  verification link in the reason (`lookup_url`, e.g. a DroneBL-style
  `.../lookup?ip={ip}` page), the way UnrealIRCd's ban reasons do
- Server notices (user mode `+s`, auto-granted alongside `+o` on `/OPER`,
  self-togglable off): every K/G-line add/remove/expiry/refused-connection,
  and every client connect, broadcast to opers who have it set -- UnrealIRCd-
  style server notices, minus the noise if an oper turns `+s` back off
- Debug channel (`[debug_channel]`, off by default): an oper-only channel
  (JOIN is refused, 401, to anyone who isn't an oper) relaying the daemon's
  own WARNING+ log lines as server NOTICEs
- CTCP (`ACTION`, `VERSION`, ...) works transparently: it's a client-side
  convention layered on `PRIVMSG`/`NOTICE`, and the server relays arbitrary
  payloads byte-for-byte
- Messaging: `PRIVMSG` / `NOTICE` (private + channel), with self-echo suppressed
- `PING`/`PONG`, `QUIT`, `WHOIS`, `WHO`, `VERSION`, `TIME`, `AWAY`, `INFO` --
  plus a server-initiated keepalive `PING` that drops unresponsive clients
  after `security.ping_timeout`
- Message of the Day from `config/ircd.motd`
- File logging (rotating) + console logging, both configurable in TOML, with a
  `debug` switch for protocol-level trace output; console output is
  color-coded by level when attached to a terminal (auto-disabled when piped,
  redirected, `--daemon`'d, or `NO_COLOR` is set)
- `--daemon`/`-d`: run detached from the terminal (POSIX double-fork, like a
  traditional Unix daemon); a PID file is always kept (`--pidfile`, default
  `./sekurircd.pid` or `$SEKURIRCD_PIDFILE`), and plain `--stop`/`--rehash`
  read it back to stop or reload config gracefully without you having to look
  up or repeat the PID/path yourself (`--rehash` sends SIGHUP -- same effect
  as `/REHASH` from an opered client, no IRC connection needed)
- `DIE`/`RESTART` (server-oper only): gracefully shut the server down, or
  shut it down and re-exec it in place (a real `execv` on the same PID); each
  can require its own extra password (`[security] die_password`/
  `restart_password`, hashed or plain-text, same as `[[operators]]`) on top
  of being an oper
- Server-to-server linking (`[links]`, hub-and-spoke, disabled by default)
  for redundancy: nicks/channels/messages mirror network-wide, plus remote
  `KILL`, `WALLOPS`, K/G-line, and oper-notice propagation; `/SQUIT` and
  `/CONNECT` for manual control, with exponential-backoff auto-reconnect on
  a leaf
- Channel services (`services/chanserv`) -- an entirely separate,
  optional process (not part of the ircd) that connects in over `[links]`
  and adds a `ChanServ` bot: `REGISTER`/`IDENTIFY`/`DROP` a channel behind a
  shared password so ops survive an empty channel instead of going to
  whoever joins first, plus `JOIN`/`PART` (GUARD), `SETPASS`, `TOPICLOCK`,
  `ACCESS` (auto-`+v`/`+h`/`+o` by hostmask or by services account),
  `SUCCESSOR` (designate who may `CLAIM` founder status if nobody's
  identified), `AKICK` (auto-kick list, same mask forms as `ACCESS`), and
  `SET MLOCK`/`DESC`/`URL`/`ENTRYMSG`

## Layout

```
sekurircd/
├── config/            # versioned config TEMPLATE (sekurircd.toml + ircd.motd)
├── src/               # source (ircd core)
├── services/          # optional, SEPARATE channel-services process (ChanServ)
├── tests/             # assert-based self-check (tests/unit.c)
├── logs/              # runtime logs (gitignored)
├── bin/               # build output (gitignored)
└── build/             # intermediate object files (gitignored)
```

Configuration is kept **separate from source**: `config/` holds templates
you copy to your deployment location; the daemon is pointed at the live
copy with `--config`.

## Dependencies

- A C11 compiler (clang or gcc) and `make`.
- OpenSSL 3 (or LibreSSL) headers/libs -- used for scrypt password hashing,
  randomness, and the TLS listener. On macOS: `brew install openssl@3` (the
  Makefile finds it automatically via `pkg-config` or the usual Homebrew
  prefixes). On Linux: `apt install libssl-dev` or equivalent.
- Everything else (`tomlc99`, `cJSON`, `uthash`/`utlist`) is vendored in
  `src/vendor/` -- no other install step.

## Quick start

```bash
# 1. build
make            # -> bin/sekurircd, bin/chanserv

# 2. configure
cp config/sekurircd.template.toml config/sekurircd.toml
cp config/ircd.motd config/ircd.motd   # already present; edit to taste
# edit config/sekurircd.toml (port, operators, [links] if you want chanserv, ...)

# 3. run it (uses config/sekurircd.toml, listens on 0.0.0.0:6667 by default)
./bin/sekurircd --config config/sekurircd.toml

# generate a password_hash for [[operators]] (prompts, no echo, prints the hash)
./bin/sekurircd --hash-password
./bin/sekurircd --version
```

To run it as a background daemon instead of a foreground process:

```bash
./bin/sekurircd --config config/sekurircd.toml --daemon --pidfile /var/run/sekurircd.pid
./bin/sekurircd --stop    --pidfile /var/run/sekurircd.pid   # graceful stop; removes the pidfile
./bin/sekurircd --rehash  --pidfile /var/run/sekurircd.pid   # reload config live; process keeps running
#    — equivalent to: kill -TERM/-HUP "$(cat /var/run/sekurircd.pid)"
#    — or skip --pidfile on all three lines to use the default ./sekurircd.pid
#      (or $SEKURIRCD_PIDFILE), same as --config falls back to
#      ./config/sekurircd.toml
```

Once daemonized, stdout/stderr are redirected to `/dev/null` -- enable
`[logging] enabled = true` in the config if you want output to go anywhere.

## Running as a systemd service

`systemd/{sekurircd,chanserv}.service` + `make install` set both daemons up
as systemd **user** units instead of managing pidfiles/backgrounding by
hand (Linux + systemd only). No `sudo`/root anywhere -- everything installs
under `$HOME`, and `systemctl --user` runs against your own user manager,
not the system one. (sekurircd/chanserv never needed root to begin with:
their ports, 6667/6697, are both >1024.) `Type=forking` + `PIDFile=` just
wraps the existing `--daemon`/`--pidfile` flags above, and `ExecReload=`
wraps `--rehash`.

```bash
make
make install
#   -> binaries in ~/.local/bin
#   -> config/sekurircd.template.toml, services.template.toml, ircd.motd in ~/.config/sekurircd
#      (never overwrites a live sekurircd.toml/services.toml already there)
#   -> state (pidfile, logs/, chanserv's JSON store) in ~/.local/state/sekurircd/{ircd,chanserv}
#   -> units in ~/.config/systemd/user
#      ($XDG_CONFIG_HOME/$XDG_STATE_HOME honored instead of ~/.config, ~/.local/state if set)

cp ~/.config/sekurircd/sekurircd.template.toml ~/.config/sekurircd/sekurircd.toml   # then edit it
systemctl --user enable --now sekurircd
# once services/services.toml is set up too (see "Channel services" below):
systemctl --user enable --now chanserv

systemctl --user reload sekurircd     # live config reload, same as --rehash
systemctl --user restart sekurircd
journalctl --user -u sekurircd -f     # only useful once [logging] enabled = true writes somewhere,
                                       # or with stdout captured -- see note above
```

By default a user unit only runs while you have an active login session; to
keep it running after logout / start it at boot before login, run (once,
still no `sudo` -- though it may prompt for your own password via polkit):
`loginctl enable-linger $(whoami)`.

`make uninstall` removes the binaries and unit files; it leaves
`~/.config/sekurircd` and `~/.local/state/sekurircd` in place so
config/state/logs survive a reinstall. Override `PREFIX`, `SYSCONFDIR`,
`STATEDIR`, or `UNITDIR` on the `make` command line to change any of the
above.

## Trying it

In one terminal start the server, then in another:

```bash
# raw protocol smoke test
nc 127.0.0.1 6667
# then type:
NICK test
USER test 0 * :Test User
# ... you should see the welcome + MOTD ...
JOIN #general
PRIVMSG #general :hello
QUIT
```

Or build and run the assert-based self-check, which exercises the message
parser, mask matching, durations, and crypto (including a scrypt-generated
vector, proving password hashes keep verifying unchanged across builds):

```bash
make check      # build + run tests/unit.c
```

**Build note:** the Makefile uses `-MMD -MP` so editing a shared header
(e.g. adding a struct field) correctly triggers a rebuild of every `.c`
that includes it -- without this, `make` only looks at `.c` mtimes and will
happily link a stale `.o` compiled against an old struct layout, which
corrupts memory in ways that are miserable to debug. If you ever add a new
build target that compiles `.c` files directly into a binary without going
through the `$(OBJ_DIR)/%.o` pattern rule, it doesn't need this (it always
recompiles from source), but any target that reuses cached `.o` files does.

```bash
make            # release build -> bin/sekurircd, bin/chanserv
make debug      # ASan+UBSan build -> bin/sekurircd-debug
make check      # build + run tests/unit.c
make clean
```

## Configuration

See [`config/sekurircd.template.toml`](config/sekurircd.template.toml). Key sections:

- `[server]` — name, network, version, `bind` (default `0.0.0.0`), `port` (default `6667`)
- `[security]` — line/param length limits, flood guard, keepalive
  `ping_interval` / `ping_timeout` (defaults 120s / 300s), `host_masking`
  (default `false`), `klines_file` (K/G-line persistence, empty = in-memory only),
  `default_user_modes` (default `""`, e.g. `"iw"`), `max_connections` /
  `max_connections_per_ip`, `reserved_nicks`
- `[messages]` — `motd` file (relative to the config file), max message length
- `[logging]` — `enabled`, `directory` (default `logs/`), `debug` (protocol trace),
  `level`, `file`, rotation `max_bytes` / `backup_count`
- `[[operators]]` — `name` / `hosts` (required ident@IP mask list, e.g.
  `["*@*"]`) + exactly one of `password_hash` (scrypt, from
  `sekurircd --hash-password` -- recommended) or legacy plain-text
  `password`, that may `/OPER`; add as many tables as you need for multiple
  ircops; none by default
- `[admin]` — `location1` / `location2` / `email` reported by `/ADMIN`; blank by default
- `[[vhosts]]` — `host` + `allowed_hosts` (ident@IP masks, not nicks) that
  `/VHOST` may activate; none by default
- `[channels]` — `restrict_creation` (default `false`) + `allowed_channels` +
  `default_modes` (default `"nt"`) + `auto_join`, see "Features" above
- `[dnsbl]` — `enabled` (default `true`, EFnet RBL), `zones`, `timeout` (default 5s),
  `action` (`"kline"` or `"reject"`), `kline_duration`, `lookup_url`
- `[tls]` — `enabled` (default `false`), `port` (default `6697`), `cert_file`
  / `key_file` (PEM, required if enabled); runs alongside `[server]`'s
  plaintext listener, never in place of it
- `[accounts]` — `enabled` (default `false`), `store_file`; backs SASL
  PLAIN, `/REGISTER`, and the `a:` EXTBAN type
- `[debug_channel]` — `enabled` (default `false`), `name` (default
  `"#server-debug"`, oper-only -- JOIN is refused to anyone else),
  `min_level` (default `"WARNING"`)
- `[links]` — `enabled` (default `false`), `mode` (`"hub"` or `"leaf"`),
  `bind`/`port` (hub), `tls`, `reconnect_delay`/`reconnect_delay_max`
  (leaf), `[[links.peers]]` entries -- see "Channel services" below for a
  worked example

Relative paths: `motd`, `tls.cert_file`, `tls.key_file` resolve against the
**config file's directory**; `logging.directory` resolves against the
**current working directory** (all also accept absolute paths).

## Adding or updating an IRC operator

An `[[operators]]` entry is a `/OPER` login: `name`, `hosts` (required
ident@IP masks it may `/OPER` from), and exactly one of `password_hash`
(recommended) or legacy plain-text `password`. This works the same way
whether you're adding a brand-new oper or rotating an existing one's
password -- there's no separate "change password" command, you just edit the
`password_hash` in place.

**1. Generate a hash** (prompts twice, no echo, prints one line -- nothing
touches disk here, you paste the output yourself):

```bash
./bin/sekurircd --hash-password
# -> scrypt$16384$8$1$3f9c1a7b2e8d4f56...$91ab...   (example, truncated)
```

**2. Edit your config file** (the live copy, not
`config/sekurircd.template.toml`) -- add a new `[[operators]]` table, or, to
rotate a password, replace the `password_hash` value on the existing one:

```toml
[[operators]]
name = "admin"
password_hash = "scrypt$16384$8$1$3f9c1a7b2e8d4f56...$91ab..."  # from step 1
hosts = ["*@*"]                     # or restrict, e.g. ["*@203.0.113.42"]
```

**3. Apply it** -- either works, no need to do both:
- **Already running:** from a client that's *already* opered (on this login
  or another one), send `/REHASH`. It reloads the whole config file live,
  `[[operators]]` included -- no reconnect needed for anyone, and no one
  gets deopered.
- **Otherwise:** restart the daemon (`sekurircd --config ...`), or
  `sekurircd --rehash --pidfile ...` against an already-running one.

**4.** `/OPER <name> <new password>` to confirm it took.

Removing an oper is the same in reverse: delete (or comment out) its
`[[operators]]` table, then `/REHASH` or restart -- anyone currently opered
under that login keeps their `+o` until they reconnect or re-`/OPER`
elsewhere; `/REHASH` doesn't retroactively deop connected clients.

## Channel services (ChanServ)

`services/chanserv` is a **completely separate, optional process** --
not part of `sekurircd`, not started by it, and not required for the ircd
to run. It connects to the ircd as an ordinary link peer (the same
`[links]` server-to-server linking feature above) and introduces one bot,
`ChanServ`, that lets a channel be registered to a password so its ops
survive an empty channel instead of going to whoever joins first.
Registrations are JSON on disk with rotating backups (`[storage]
backup_count` in `services.toml`, default 5) so a corrupted file or bad
write doesn't erase them -- the newest readable backup is loaded
automatically if the live file won't parse.

**Enabling it** (two independent processes, both need config):

1. On the **ircd side** (`config/sekurircd.toml`), turn on `[links]` in hub
   mode and add a peer entry for the bot -- `password_hash` (scrypt, from
   `sekurircd --hash-password`) is preferred over plain `password` here, the
   same as `[[operators]]`, so this config doesn't hold the raw secret (the
   services side still needs the actual plain secret to send it):
   ```toml
   [links]
   enabled = true
   mode = "hub"

   [[links.peers]]
   name = "services.sekurircd.local"
   password_hash = "scrypt$16384$8$1$<salt-hex>$<digest-hex>"
   ```
2. On the **services side**, copy the template and point it at the same
   link port/password:
   ```bash
   cp services/services.template.toml services/services.toml
   # edit services/services.toml: [link] host/port = the ircd's [links]
   # bind/port, name/password = the [[links.peers]] entry above
   ```

**Running it** -- same shape as `sekurircd` itself:

```bash
# foreground (Ctrl-C to stop)
./bin/chanserv --config services/services.toml

# as a detached daemon (POSIX double-fork)
./bin/chanserv --config services/services.toml --daemon --pidfile services/chanserv.pid
./bin/chanserv --stop --pidfile services/chanserv.pid
#    — equivalent to: kill -TERM "$(cat services/chanserv.pid)"
```

`--daemon` writes the running process's PID to a pidfile (default
`./chanserv.pid`, or `--pidfile <path>` to use another location), and
`--stop` reads that same file back to find the process -- neither side
needs the PID typed in by hand. `--stop` sends SIGTERM and waits for the
process to actually exit before returning; the pidfile is removed for you
on a clean shutdown, and starting a second `--daemon` while one is already
running (per that same pidfile) is refused rather than clobbering it. Both
SIGINT and SIGTERM trigger a clean disconnect from the ircd either way
(daemonized or not). If the ircd isn't up yet, or the link drops, chanserv
retries the connection rather than exiting.

**Using the bot**, from any IRC client already connected to the ircd:

```
/msg ChanServ REGISTER #mychannel hunter2         # while you're opped on #mychannel
/msg ChanServ IDENTIFY #mychannel hunter2         # on every new connection, to reclaim founder status
/msg ChanServ DROP #mychannel hunter2             # unregister
/msg ChanServ JOIN #mychannel hunter2             # ChanServ joins and stays -- see below
/msg ChanServ PART #mychannel hunter2             # ChanServ leaves (undoes JOIN)
/msg ChanServ SETPASS #mychannel hunter2 newpass  # change the password in place
/msg ChanServ TOPICLOCK #mychannel ON hunter2     # remember + restore the topic across a restart
/msg ChanServ INFO #mychannel                     # registration date + GUARD/TOPICLOCK status
/msg ChanServ ACCESS #mychannel ADD *@trusted.example h hunter2  # auto-+h on JOIN from that host
/msg ChanServ ACCESS #mychannel ADD =alice o hunter2             # auto-+o once "alice" is identified
/msg ChanServ ACCESS #mychannel DEL *@trusted.example hunter2
/msg ChanServ ACCESS #mychannel LIST
/msg ChanServ HELP
```

`REGISTER` requires you to currently be a channel operator on the target
(proves possession); `IDENTIFY` re-ops you immediately if you're already in
the channel, and auto-ops you on every future `JOIN` for the rest of that
connection -- it is **not** remembered across reconnects, so it must be
repeated each time you connect (same as any other services network). There
is no account system tied to ChanServ itself: the password belongs to the
channel record, so anyone who knows it can `IDENTIFY` as its founder.

**`JOIN`/`PART`: keeping ChanServ permanently in the channel.** A channel is
destroyed the moment it has no members left -- `JOIN` makes ChanServ itself
sit in the channel as a member, which means it can never go empty (and so
can never be destroyed or squatted) even with every human gone. This is
persisted on the registration (survives a `chanserv` restart -- it rejoins
every such channel automatically right after linking) and self-healing: if
someone `/KICK`s ChanServ out, it rejoins immediately, since a kick doesn't
turn the setting off. `PART` turns it back off and makes ChanServ leave.
Off by default -- registering a channel alone does not make ChanServ join
it. Every time ChanServ actually (re)joins under `GUARD` -- including the
automatic rejoin after its own reconnect -- it also deops anyone in the
channel who isn't founder-identified this session (with a `NOTICE` telling
them to `IDENTIFY`). This closes the gap where a full **ircd** restart
empties the channel and a stranger wins the race to join it first,
auto-opping themselves before ChanServ reconnects.

**`TOPICLOCK`**: `TOPICLOCK #chan ON|OFF <password>` makes `chanserv`
remember the channel's topic (recorded on every change while on) and
restore it whenever `GUARD` (re)joins and the live channel's topic doesn't
match -- topics are in-memory only in the ircd, so a full restart would
otherwise lose them even for a `GUARD`ed channel.

**`SETPASS`/`INFO`**: `SETPASS #chan <old> <new>` changes a channel's
password in place -- without it, changing a password meant `DROP` +
`REGISTER` from scratch, which silently lost the `GUARD` (`JOIN`/`PART`)
setting and required being an op again. `INFO #chan` is a read-only query
(no password needed) showing when a channel was registered and whether
`GUARD`/`TOPICLOCK` are currently on.

**Brute-force protection**: like `/OPER`'s lockout rule, every command
that checks an existing password (`IDENTIFY`, `DROP`, `JOIN`, `PART`,
`SETPASS`'s old-password check) locks that *nick* out of ChanServ password
checks entirely, network-wide, for a short window after repeated wrong
attempts in a row -- not just on the channel being targeted, so it also
stops one nick grinding through passwords across many channels. The
lockout clears on `QUIT` (a fresh connection gets a fresh count) and
follows a nick change.

**`/CTCP ChanServ VERSION`** gets a real reply (`ChanServ v<version> --
SekurIRCd channel services ...`), not silence -- most clients show a bot's
CTCP VERSION reply directly in the query window, so an unanswered one reads
as broken rather than "not implemented." Every other CTCP (`ACTION`, `PING`,
`CLIENTINFO`, ...) is silently ignored, same as an unrecognized text
command -- no error spam back to whoever's probing.

**`ACCESS`/`AKICK`**: `ACCESS #chan ADD <mask> <v|h|o> <password>` lets a
founder grant `+v`/`+h`/`+o` on every future `JOIN` to `#chan` from a
matching connection, without handing out the channel password itself.
`AKICK #chan ADD <mask> <password>` auto-kicks anyone matching `<mask>` on
`JOIN` instead. Both take the same `<mask>` forms:

- a bare host (`trusted.example`, `1.2.3.4`), `ident@host`
  (`*@trusted.example`, `~user@1.2.3.4`), or a full `nick!ident@host` mask
  (`Helper!*@trusted.example`) -- shorthand forms are wildcard-expanded to a
  full mask (e.g. `*@trusted.example` becomes `*!*@trusted.example`). The
  **host is always required**, even in the full form: a mask may optionally
  pin a specific nick too, but it is never *just* a nick, so granting access
  to `Helper!*@trusted.example` can't be defeated simply by someone else
  grabbing the nick `Helper` from a different host later -- unlike a plain
  nick-keyed list, which is exactly what that would let happen. This form
  is only as strong as the mask itself: one covering a dynamic/shared host,
  or a `host_masking`-enabled deployment's random per-connection cloak, is
  either spoofable or simply never matches.
- `=accountname` instead matches by services account -- the same SASL/
  `/REGISTER` identity `[accounts]` backs -- rather than any host at all.
  It only fires once the joiner has actually identified that session; an
  unidentified connection, even sitting on a matching nick, never matches.
  This is the one to use under `host_masking`, and generally the more
  durable choice once your users have accounts, since it survives host and
  IP changes entirely.

`ACCESS`/`AKICK ... DEL <mask> <password>` removes an entry (pass it back
exactly as added, or in its shorthand form -- both normalize the same way);
`ACCESS`/`AKICK ... LIST` (no password needed) shows the current list as
normalized entries, not resolved nicks. `ADD`/`DEL` go through the same
password-lockout protection as every other mutating command above.

## Security notes

No `eval`/`system`/shell-out anywhere in the request path. Enforced input
limits (line length, param count, nick length), a per-client flood guard,
and per-connection isolation so one bad client cannot crash the daemon.
Enable `[tls]` for native SSL/TLS (default port `6697`) -- a self-signed
certificate still encrypts the connection, so most clients just need "only
allow trusted certificates" unchecked; the `+z` channel mode can restrict a
channel to clients who connected that way. Restrict `[server].bind` for
extra network-level isolation. Enable `[security] host_masking` to keep
users' real IPs/hostnames off the wire (still visible to an oper, or to the
user themselves, via `WHOIS`). Use `[[operators]] password_hash` (scrypt,
via `sekurircd --hash-password`) instead of plain-text `password` so
`/OPER` credentials aren't recoverable from a leaked config file. Built
with `-Wall -Wextra`; `make debug` builds an ASan+UBSan variant for catching
memory-safety issues during development.
