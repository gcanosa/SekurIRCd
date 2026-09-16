# SekurIRCd in C — port plan

## Status (v1.0.2) — fully implemented

Both binaries build clean (zero warnings, `-Wall -Wextra`) and are verified
working end-to-end with real TCP/TLS clients: `sekurircd` (registration
burst, the full IRCv3 cap bundle, channels/modes/messaging, oper commands,
daemon lifecycle, DNSBL/ident/rDNS gating, and server-to-server linking in
both hub and leaf modes) and `chanserv` (links in, REGISTER/IDENTIFY/DROP/
INFO/HELP/SETPASS/TOPICLOCK/ACCESS/AKICK/SUCCESSOR/SET/GUARD against a JSON
store with rotating backups). `make check`'s 22-assertion suite passes; a
`leaks --atExit` run through a full connect→join→message→link→quit→
shutdown cycle -- including a live two-node hub/leaf pair -- showed 0 bytes
leaked.

This shipped faster/rounder than the phase list below: `net.c`/`server.c`/
`client.c`/`channel.c`/`cmd_*.c` cover phases 1-7 (including the full IRCv3
cap bundle and TLS, which both landed early), and a deliberately simplified
`link.c` (IRC-line based, not the JSON/full-mirroring design originally
sketched below, and now supporting leaf-dial + `/CONNECT` on top of the
original hub-only MVP) plus `services/chanserv.c` cover phases 8-9 in full.
See `README.md` for the current feature list. The rest of this file is the
original pre-implementation plan -- still the reference for scope/design,
except where "Status" notes above override it (the link protocol section
below describes the original JSON design that was NOT what got built --
see `src/link.h`'s own doc comment for what's actually implemented).

Config/data files copied verbatim from the sibling Python project
(`../python/sekurircd`) for testing and real deployment: `config/
sekurircd.toml`, `config/accounts.json`, `config/tls/{cert,key}.pem`,
`services/services.toml`, `services/chanserv.json` -- all git-ignored (only
the `.template.toml` files are meant to be committed, same convention as
the Python project). The live config's `[[operators]]`/`[[links.peers]]`
scrypt hashes and the TLS cert/key all worked unchanged against this C
port, which is the whole point of reusing OpenSSL's scrypt/TLS rather than
inventing anything -- see the "Dependencies" table above.

A later pass ("proceed until fully implemented") filled in nearly everything
else from the Python command table: halfop, ban exceptions/INVEX, EXTBAN
`a:`, STATUSMSG, INVITE/KNOCK, K/G-lines (persisted + enforced on connect),
WHOWAS, USERHOST/ISON/MONITOR/SILENCE/SETNAME/GLOB, VHOST/CHGHOST/SETHOST,
STATS/TRACE/UPTIME/SERVLIST/SQUERY/LINKS/MAP, SAJOIN/SAPART/SAMODE, and
DIE/RESTART's extra-password gate + real `execv` restart.

A final pass ("implement what is remaining") closed every gap that was
still open at that point: the rest of the IRCv3 cap bundle beyond bare
negotiation + sasl (message-tags, server-time, multi-prefix, account-
notify, chghost, away-notify, echo-message, setname, invite-notify,
standard-replies), DNSBL/ident/rDNS lookups (via `worker.c`'s thread pool,
gating registration without blocking the event loop), ChanServ's ACCESS/
GUARD/SETPASS/TOPICLOCK/SUCCESSOR/AKICK/SET (wired over the link protocol's
new JOIN/PART/MODE/KICK/WHOISCHAN/SVCJOIN commands), and leaf-dials-a-hub
mode + `/CONNECT` (`link_connect_leaf`/`link_leaf_tick` in `link.c`: dials
the configured uplink on startup, reconnects with exponential backoff on
failure, and `/CONNECT` forces an immediate retry). `README.md` has the
full, current feature list -- nothing from the original Python command
table is intentionally left unported.

**Two real bugs found by testing this pass, not hypothetical:**
1. `unlink_connection` (server.c) assumed every client passed to it had
   been linked into `all_clients`. A service pseudo-client (ChanServ, `fd
   == -1`) never is (`server_add_connection` is only called for a real
   accepted socket), so its `all_prev`/`all_next` are both NULL from
   `calloc` -- indistinguishable from "the sole entry in the list". Removing
   one (e.g. on `/SQUIT`, or any ordinary link drop) hit the `else` branch
   and set `srv->all_clients = NULL` unconditionally, silently dropping
   *every* other connected client from the poll loop -- they kept their
   open sockets and stayed in the `users` hash (still findable by nick,
   e.g. via `/WHOIS`) but were never read or written again. A queued reply
   (a `/SQUIT` confirmation NOTICE, in the case that surfaced it) would sit
   in `sbuf` forever. Fixed by guarding on `fd >= 0`; also had to fix
   shutdown, which had come to rely on the same "service clients are in
   all_clients" assumption to free them -- they're now freed via their
   owning `link_conn_t`, and `srv->users`'s own uthash bucket-array
   bookkeeping is released with `HASH_CLEAR` instead of a bare `= NULL`
   (uthash keeps that internal structure attached to the head pointer
   separately from the entries themselves).
2. `/RESTART`'s `execv` re-exec keeps the same PID and deliberately leaves
   the pidfile in place. The re-exec'd process's own startup then read that
   *same* pidfile, saw its *own* PID, concluded via `kill(pid, 0)` that
   "yes, that process is alive" (true -- it's asking about itself), and
   refused to start as "a second instance" -- so `/RESTART` reliably killed
   the daemon instead of restarting it. Fixed by short-circuiting
   `pidfile_is_live()` when the PID on disk equals `getpid()`.

Both were caught by exercising the actual running binaries end-to-end
(sockets, real link drops, a real `execv`), not by inspection -- worth
remembering next time a change here looks obviously correct on the page.

## Context

`../python/sekurircd` is a ~7k-line pure-stdlib Python IRC daemon (RFC 1459/2812 + IRCv3),
plus a ~1.3k-line ChanServ. The goal is a C rewrite in `/Users/ethernet/coding/sekurircd`
(currently empty) with the same features and config. It should have as few external
dependencies as possible without rewriting mature pieces ourselves.

Decisions already made with the user:
- **TLS and crypto: system OpenSSL.** It provides TLS, `EVP_PBE_scrypt`, `RAND_bytes`
  and `CRYPTO_memcmp`, so existing `scrypt$N$r$p$salt$digest` hashes keep verifying.
- **Parsing: vendored single-file libraries.** `tomlc99` (cktan/tomlc99) for TOML and `cJSON` for JSON.
  Existing `sekurircd.toml`, `accounts.json`, the klines file and `chanserv.json` load unchanged.
- **Scope.** Everything in the core daemon, the debug log channel, hub/leaf links and a
  ChanServ written in C.
  - **Dropped:** the GitHub monitor. A `[github_monitor]` table is ignored with a warning.
  - **Links:** they do *not* need to interoperate with Python nodes. We design a new, simpler
    link protocol.
- **Platforms: macOS and Linux**, one `poll()` event loop, single-threaded like the asyncio version.

The Python code, `docs/irc-protocol-reference.md` and the tests are the behavioral spec.
The docs file is authoritative for numerics, the order of the registration burst, ISUPPORT
and CAP semantics.

## Dependencies (complete list)

| What | Source | Why not write it |
|---|---|---|
| OpenSSL 3 / LibreSSL | system (`pkg-config openssl`, `brew --prefix openssl@3` on macOS) | TLS and crypto should never be hand-rolled |
| tomlc99 (cktan/tomlc99, `toml.c/h`) | vendored in `src/vendor/`, MIT | full TOML incl. `[[arrays]]` |
| cJSON (`cJSON.c/h`) | vendored, MIT | data files |
| uthash (`uthash.h`, `utlist.h`) | vendored header-only, BSD | hash tables and lists; C has none in its stdlib |
| pthreads, libc, POSIX | system | — |

Nothing else. We write our own code where the job is small and specific: the IRC parser,
`*`/`?` mask matching (Python escapes brackets, so `fnmatch(3)` is wrong), the rotating log,
the event loop and the resolver worker pool.

## Layout

```
Makefile                 # plain make; `make`, `make debug` (ASan+UBSan), `make check`
src/vendor/              # toml.c/h, cJSON.c/h, uthash.h, utlist.h
src/main.c               # app.py: argv, --daemon/--pidfile/--stop/--rehash/--hash-password, signals, execv restart
src/config.c/.h          # config.py: tomlc99 -> struct config, validation, same keys/defaults, rehash swap
src/log.c/.h             # logging_setup.py: console (ANSI if TTY && !NO_COLOR), size-rotating file, debug-channel hook
src/net.c/.h             # poll loop, listeners, nonblocking sockets, OpenSSL wrap, rbuf/sendq, 1s tick
src/worker.c/.h          # pthread pool: rDNS, ident, DNSBL, scrypt verify; results via self-pipe into poll
src/proto.c/.h           # protocol.py: parse/build/escape, tags, validators, casefold, mask_match, numerics, durations
src/crypto.c/.h          # passwords.py: scrypt hash/verify, random hex, constant-time compare
src/client.c/.h          # client.py: struct client (local OR remote), flood guard, send/reply
src/channel.c/.h         # channel.py: members (rank bitmask), modes, bans/excepts/invex, EXTBAN a:
src/server.c/.h          # server.py: registries, welcome/ISUPPORT/LUSERS/MOTD, klines, notify_opers, rehash
src/accounts.c/.h        # accounts.py: cJSON store, atomic tmp+rename save
src/cmd.c                # commands.py: dispatch table {name, handler, min_params, needs_reg, oper_only}
src/cmd_reg.c            #   NICK USER PASS CAP AUTHENTICATE REGISTER PING PONG QUIT
src/cmd_chan.c           #   JOIN PART TOPIC NAMES LIST INVITE KNOCK KICK MODE
src/cmd_user.c           #   PRIVMSG NOTICE WHOIS WHO WHOWAS AWAY SETNAME USERHOST ISON MONITOR SILENCE
src/cmd_oper.c           #   OPER DIE RESTART KILL K/GLINE UN* SAJOIN SAPART SAMODE CHGHOST SETHOST VHOST WALLOPS STATS REHASH CONNECT SQUIT
src/cmd_info.c           #   VERSION TIME INFO ADMIN MOTD HELP LUSERS UPTIME TRACE LINKS MAP SERVLIST SQUERY
src/link.c/.h            # link.py redesigned (see below); also used by chanserv as leaf client
services/chanserv.c      # services/chanserv.py -> separate `chanserv` binary
tests/unit.c             # assert-based: parser, escape, mask_match, casefold, durations, scrypt vector
tests/e2e.py             # stdlib-only black-box tests (socket + subprocess) against the built binary
config/                  # copy sekurircd.template.toml + ircd.motd as-is (minus [github_monitor])
```

The Python module-to-file mapping is 1:1 wherever possible, which keeps porting a
side-by-side read. Nothing else gets its own file.

## Core design notes

- **Event loop:** one `poll()` array rebuilt each iteration. There is no timer heap:
  a 1-second tick scans all connections for PING and timeout, the registration timeout,
  K-line expiry, link pings and leaf reconnect backoff.
  `// ponytail: O(n) poll+tick, fine to a few thousand clients; kqueue/epoll backend if it matters.`
- **Memory model:**
  - `malloc`/`free` with clear ownership: the server owns clients and channels.
  - Fixed-size fields for nick, user, host and realname (bounded by config maxima and
    compile-time caps).
  - uthash tables for `users` (casefolded nick), `channels`, channel members (client →
    rank bits), MONITOR, WHOWAS (ring buffer) and klines.
  - A client is freed only at the end of a loop iteration (deferred-free list), so no handler
    ever touches a dangling pointer after a KILL or QUIT in a broadcast.
- **Output:** everything goes through `proto_build()`, which strips `\r\n\0` (the existing
  injection invariant). Each client has a bounded sendq: over the limit means disconnect
  with "SendQ exceeded". Only `snprintf` and length-checked copies are allowed, never
  `sprintf`/`strcpy`.
- **Input:** the `server._read_loop` choke point stays as-is: line length, param count,
  flood guard, then parse, then dispatch. The dispatch table enforces `min_params` and the
  registration gate, so handlers never index a missing param. This replaces Python's
  per-handler exception isolation.
- **Blocking work off the loop:**
  - Jobs are `getnameinfo` + forward-confirm (rDNS), `getaddrinfo` (DNSBL), ident (a blocking
    socket with `SO_RCVTIMEO`) and scrypt verification (OPER, SASL, REGISTER, link password).
  - Each job carries a connection id (`uint64`), never a pointer. A late result for a gone
    client is dropped, and the loop enforces the timeout by ignoring late results.
  - The job queue is bounded. When it is full, rDNS/ident/DNSBL fail open, the same policy
    as Python.
- **TLS:** a second listener, nonblocking `SSL_read`/`SSL_write` with WANT_READ/WANT_WRITE
  mapped onto poll events, user mode `+Z` and channel mode `+z`. Cert and key load at startup
  only, as in Python.
- **Rehash:** load a new `struct config`; only on success swap it in and free the old one.
  bind/port/TLS are unchanged. It is triggered by SIGHUP (a flag checked in the loop) and by `/REHASH`.
- **Cloak format:** a tiny `{token}`/`{network}` substitution in place of Python's `str.format`.

## Link protocol (new, IRC-line based)

This reuses `proto.c` instead of JSON, so there is one parser for everything.
The semantics are copied from Python; only the encoding changes:
- **Handshake:** `PASS <secret>`, then `SERVER <name> <protover> :<desc>` in both directions,
  optionally over TLS. The hub checks `password_hash` on the worker pool.
- **Burst:** `NICK` with all user state (`nick user host realhost ip signon umodes account
  server :realname`), then for each channel `CHANTS #c <created>` → `SJOIN #c <modes> :@nick +nick …`,
  then `TOPIC`, `KLINE`, and finally `EOB`.
- **Live events:** NICK, JOIN, PART, QUIT, KICK, TOPIC, MODE, UMODE, AWAY, CHGHOST, SETNAME,
  INVITE, KILL, WALLOPS, SNOTICE, KLINE, UNKLINE, PRIVMSG, NOTICE, PING, PONG, SQUIT,
  LINKUP and LINKDOWN.
- **Kept from Python:**
  - strict hub-and-spoke topology, with the hub as the only judge of nick collisions
    (the introducing side is KILLed)
  - channel TS reconciliation, where the older `created` keeps its ops
  - full-mirror state, with only PRIVMSG/NOTICE content routed by interest
  - purge-by-origin plus a relayed SQUIT on netsplit
  - LINKUP/LINKDOWN feeding `/LINKS` and `/MAP`
  - leaf reconnect with doubling backoff
  - `service` flag on NICK for SERVLIST/SQUERY
- **Remote users** are the same `struct client` with `link != NULL` and no socket, so there is
  no duck typing. `client_send()` on a remote user relays only PRIVMSG/NOTICE. One broadcast
  becomes one wire line per link through a global `broadcast_serial` stamp on the link, which
  replaces Python's `call_soon` coalescing.

## ChanServ

- **Process model:** a separate `chanserv` binary, as in Python, so "services on" just means the
  process is running. It links `proto.o crypto.o link.o log.o` plus tomlc99/cJSON and runs in
  leaf-only mode with its own small `poll` loop from `net.c`.
- **Config and data:** reads `services.toml` and the existing `chanserv.json` schema
  (including rotating `.bakN` backups and corruption fallback).
- **Commands:** REGISTER, IDENTIFY, DROP, JOIN, PART, SETPASS, TOPICLOCK, INFO, ACCESS,
  SUCCESSOR, AKICK and SET (MLOCK/DESC/URL/ENTRYMSG). Also the join guard and `+r` handling,
  still accepted only over the trusted link path.
- **CLI:** `-d`, `--pidfile` and `--stop`, sharing the helpers in `main.c`.

## Phases (each ends runnable and tested)

1. **Skeleton:**
   - Makefile, vendored libraries
   - `log`, `config` (the full schema, loading the current `config/sekurircd.toml`)
   - `crypto` with `--hash-password`
   - `proto` with `tests/unit.c`, `make check`
2. **Core connection:**
   - `net` poll loop and plaintext listener
   - registration with the welcome burst (001–005 ISUPPORT, LUSERS, MOTD)
   - PING/PONG keepalive and timeout, flood guard, sendq, QUIT
   - `--daemon`/`--pidfile`/`--stop`/`--rehash` and signals
   - Test with `nc`, irssi and weechat.
3. **Channels and messaging:**
   - JOIN/PART/TOPIC/NAMES/LIST (ELIST)/INVITE/KNOCK/KICK
   - full MODE (user and channel modes, halfop rules, bans/excepts/invex, EXTBAN a:)
   - PRIVMSG/NOTICE including STATUSMSG
   - WHOIS/WHO/WHOWAS, AWAY, USERHOST/ISON, MONITOR, SILENCE
   - the info commands
4. **IRCv3 and accounts:**
   - CAP LS 302/REQ/END with all 13 caps plus sasl
   - message tags and server-time
   - accounts store, SASL PLAIN and REGISTER (scrypt on the worker pool)
5. **Oper and security:**
   - OPER with host masks, KILL, K/G-lines (persisted), SA*, CHGHOST/SETHOST/VHOST
   - WALLOPS, STATS, REHASH, DIE/RESTART (`execv`)
   - connection limits, reserved nicks, cloaking
   - default user modes, auto_join and oper_auto_join, restrict_creation
   - debug log channel
6. **Async lookups:** worker pool, then rDNS, ident, DNSBL and the auto-K-line.
7. **TLS:** TLS listener with `+Z`/`+z`.
8. **Links:**
   - protocol above, hub/leaf, burst
   - TS reconciliation and collisions
   - SQUIT/CONNECT/LINKS/MAP, TLS links
9. **ChanServ binary.**
10. **Docs:**
    - README with build and run instructions
    - port `irc-protocol-reference.md`, rewriting the link-protocol section
    - CLAUDE.md for the C tree

Expect about 15–20k lines of C in total. The mapping is mechanical except for `net.c`,
`worker.c` and `link.c`.

## Python files to read side by side while porting

- `src/sekurircd/protocol.py`: parse/build/escape rules, validators, the `N` numerics
- `src/sekurircd/server.py`: `_read_loop` limits, `_send_welcome` token list, LUSERS, KlineEntry
- `src/sekurircd/commands.py`: every handler, `_CAP_ATTRS`, `_apply_channel_mode`, registration gate
- `src/sekurircd/channel.py`: `CHAN_MODES`, `mode_takes_arg`, `_mask_hit`, `has_rank_at_least`
- `src/sekurircd/config.py`: every key, default and validation rule, including path-resolution rules
- `src/sekurircd/link.py`: `_burst_events`, `_on_chants`, `purge_origin`, collision handling
- `services/chanserv.py`: ChannelStore backups, command set, guard_join
- `docs/irc-protocol-reference.md`: the authoritative wire behavior
- `tests/test_*.py`: scenarios to port into `tests/e2e.py`

## Verification

- **`make check`:** unit asserts for the parser (tags, trailing param, 15-param cap, CR/LF
  injection stripped), mask matching (literal `[`), casefold and durations. Also a scrypt vector
  generated once with Python `hashlib.scrypt` and pasted in, proving existing hashes verify.
- **`make debug && python3 tests/e2e.py`:**
  - The binary is built with ASan/UBSan, so any memory error fails the run.
  - Test scenarios are ported from the Python suite: registration burst order, CAP flow,
    SASL, JOIN/NAMES/MODE edge cases, bans and EXTBAN, flood disconnect, K-lines, TLS
    (via `ssl` from Python's stdlib), rehash and DIE.
  - Link tests start a hub and a leaf on different ports and cover cross-server
    JOIN/PRIVMSG/WHOIS, killing the leaf (netsplit QUITs) and relinking with a conflicting
    channel (TS ops).
  - ChanServ tests start the hub and `chanserv` and run REGISTER, IDENTIFY and the join guard.
- **Manual:** run with the user's current `config/sekurircd.toml`, `accounts.json` and
  `chanserv.json` copied over. Log in with an existing account, and connect irssi, weechat
  and The Lounge over plaintext and TLS.
- **Leak check:** macOS `leaks --atExit -- ./sekurircd` (or valgrind on Linux) after an
  e2e run plus `/DIE`.
