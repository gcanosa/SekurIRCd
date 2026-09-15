# SekurIRCd (C)

A C port of [SekurIRCd](../python/sekurircd) — a lightweight IRC daemon
(RFC 1459/2812 + IRCv3 CAP) — plus its ChanServ channel-registration
service. See `plans/python-sekurircd-could-you-make-ticklish-rabin.md` for
the full port plan and design notes.

## Status: v1.0.1 — fully implemented, both the daemon and the service start and work

- **`sekurircd`**: full registration burst, NICK/USER/CAP/PING/QUIT/
  AUTHENTICATE; the full IRCv3 cap bundle (message-tags, server-time,
  multi-prefix, account-notify, chghost, away-notify, echo-message,
  setname, invite-notify, standard-replies, sasl); channels (JOIN/PART/
  TOPIC/NAMES/LIST/KICK/INVITE/KNOCK/MODE with op/halfop/voice, keys,
  limits, bans/exceptions/INVEX, `+z` secure-only, EXTBAN `a:`, STATUSMSG
  `@%+`); PRIVMSG/NOTICE (SILENCE, +d CTCP suppression)/WHOIS/WHO/WHOWAS/
  AWAY/SETNAME/USERHOST/ISON/MONITOR/GLOB; OPER (lockout after repeated bad
  attempts)/KILL/WALLOPS/REHASH/DIE/RESTART (real `execv` re-exec)/VHOST/
  CHGHOST/SETHOST/KLINE/GLINE/UNKLINE/UNGLINE (persisted, enforced on
  connect)/SQUIT/CONNECT/STATS/TRACE/SERVLIST/SQUERY/LINKS/MAP/SAJOIN/
  SAPART/SAMODE; SASL PLAIN + `/REGISTER` accounts (`WHOIS` 330); DNSBL,
  ident, and reverse-DNS lookups gating registration (worker-thread pool,
  never blocks the event loop); a TLS listener (`+Z`/`+z`); server-to-
  server linking in both **hub** (accepts) and **leaf** (dials the
  configured uplink on startup, reconnects with exponential backoff, and
  supports manual `/CONNECT` to retry immediately) modes;
  `--daemon`/`--pidfile`/`--stop`/`--rehash`; colored console + rotating
  file logging.
- **`chanserv`**: links to the ircd as a service, introduces its bot nick,
  and answers REGISTER/IDENTIFY/DROP/INFO/HELP/SETPASS/TOPICLOCK/ACCESS
  (ADD/DEL/LIST)/AKICK (ADD/DEL/LIST)/SUCCESSOR (SET/CLAIM)/SET (MLOCK/
  DESC/URL/ENTRYMSG)/GUARD (auto-join/part, enforcing AKICK and ENTRYMSG on
  join via a scoped `SVCJOIN` link notification), all backed by
  scrypt-hashed passwords in a JSON store with rotating backups.
- Verified end-to-end with real TCP and TLS clients against both a
  synthetic config and the actual production config/certs/passwords copied
  from the Python project — registration, every channel/mode/rank
  interaction above, STATUSMSG delivery scoped correctly by rank, K-line
  enforcement, oper tooling, `/SQUIT` and `/RESTART` (confirmed the process
  actually survives a real `execv` re-exec on the same PID and keeps
  serving), a live two-node hub/leaf pair (startup auto-dial, `/SQUIT` +
  automatic backoff reconnect, and manual `/CONNECT` beating a long backoff
  window), and leak-checked clean (`leaks --atExit`, 0 bytes leaked)
  through connect → join → message → link → quit → shutdown.
- **Two real bugs found and fixed by this testing** (not hypothetical --
  see the plan doc for the write-up): removing a service pseudo-client
  (e.g. after `/SQUIT` or any link drop) was nulling out the *entire*
  connected-client list, silently dropping every other client from the
  poll loop; and `/RESTART`'s re-exec'd process refused to start because
  its own unchanged pidfile named its own (unchanged) PID.

**Build note:** the Makefile uses `-MMD -MP` so editing a shared header
(e.g. adding a struct field) correctly triggers a rebuild of every `.c`
that includes it. Without this, `make` only looks at `.c` mtimes and will
happily link a stale `.o` compiled against an old struct layout -- which
corrupts memory in ways that are miserable to debug (this actually happened
once during development: `net.c`'s and `link.c`'s different ideas of
`struct server`'s layout silently aliased two fields). If you ever add a
new build target that compiles `.c` files directly into a binary without
going through the `$(OBJ_DIR)/%.o` pattern rule, it doesn't need this (it
always recompiles from source), but any target that reuses cached `.o`
files does.

## Dependencies

- A C11 compiler (clang or gcc) and `make`.
- OpenSSL 3 (or LibreSSL) headers/libs — used for scrypt password hashing,
  randomness, and the TLS listener. On macOS: `brew install openssl@3` (the
  Makefile finds it automatically via `pkg-config` or the usual Homebrew
  prefixes). On Linux: `apt install libssl-dev` or equivalent.
- Everything else (`tomlc99`, `cJSON`, `uthash`/`utlist`) is vendored in
  `src/vendor/` — no other install step.

## Build

```bash
make            # release build -> bin/sekurircd, bin/chanserv
make debug      # ASan+UBSan build -> bin/sekurircd-debug
make check      # build + run tests/unit.c
make clean
```

## Run the ircd

```bash
cp config/sekurircd.template.toml config/sekurircd.toml
cp config/ircd.motd config/ircd.motd   # already present; edit to taste
# edit config/sekurircd.toml (port, operators, [links] if you want chanserv, ...)
./bin/sekurircd --config config/sekurircd.toml

./bin/sekurircd --hash-password        # generate a [[operators]] password_hash
./bin/sekurircd --version

# background daemon lifecycle
./bin/sekurircd --config config/sekurircd.toml --daemon --pidfile /var/run/sekurircd.pid
./bin/sekurircd --stop    --pidfile /var/run/sekurircd.pid
./bin/sekurircd --rehash  --pidfile /var/run/sekurircd.pid
```

## Run ChanServ

1. In `config/sekurircd.toml`, enable hub-mode linking and add a peer entry:
   ```toml
   [links]
   enabled = true
   mode = "hub"
   port = 7000

   [[links.peers]]
   name = "services.sekurircd.local"
   password_hash = "scrypt$..."   # from --hash-password
   ```
2. `cp services/services.template.toml services/services.toml` and set its
   `[link] password` to the same secret (plaintext here — this side has to
   send it).
3. `./bin/chanserv --config services/services.toml` (same `-d`/`--pidfile`/
   `--stop` flags as `sekurircd`).
4. From any client: `/msg ChanServ HELP`, `/msg ChanServ REGISTER #chan
   <password>`, `/msg ChanServ IDENTIFY #chan <password>`, `/msg ChanServ
   DROP #chan <password>`, `/msg ChanServ INFO #chan`.

`config/` and `services/` follow the same convention as the Python
project: only the `*.template.toml` files (and `ircd.motd`) are meant to be
committed; a live `sekurircd.toml`/`services.toml` is git-ignored.

## Tests

`tests/unit.c` is an assert-based self-check of the parser, mask matching,
durations, and crypto (including a hashlib.scrypt-generated vector, proving
password hashes from the Python daemon's config/accounts.json/chanserv.json
keep verifying unchanged). `make check` builds and runs it.
