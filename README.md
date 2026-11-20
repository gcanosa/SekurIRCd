# SekurIRCd

A small, **secure** IRC server written in C. One program, no runtime dependencies beyond OpenSSL, and it
works with the clients you already use: weechat, irssi, The Lounge, Kiwi and other standard IRC clients.

**Docs, guides and the config wizard: <https://gcanosa.github.io/SekurIRCd/>**

## Why SekurIRCd

- **Secure by default.** Built-in TLS, scrypt-hashed passwords, host cloaking, flood limits and an optional
  protection layer (DNSBL blacklists and an open-proxy scanner).
- **Modern.** IRCv3 (chat history, multiline messages, SASL, read markers and more), IPv6, WebSocket, and a web
  chat client that ships with the server.
- **Accounts and services included.** NickServ and ChanServ run as one process for the whole network. Turn on
  *always-on* and your nick stays in its channels while you are offline.
- **Grows with you.** Link several servers into a network (hub and leaves over TLS), and decide how far each
  leaf's IRC operators can reach.
- **Easy to run.** A setup wizard writes your config, one wrapper script starts and stops everything, and an
  optional stats dashboard shows the network at a glance.
- **Familiar.** UnrealIRCd-style channel modes, extbans and flood rules.

## Quick start

You need a C11 compiler, `make` and OpenSSL 3 (macOS: `brew install openssl@3`; Debian/Ubuntu: `apt install libssl-dev`). On FreeBSD, OpenBSD and NetBSD install `gmake` and use it in place of `make`; on Windows build with Cygwin (see the install docs).

```bash
git clone https://github.com/gcanosa/SekurIRCd.git && cd SekurIRCd
make                  # builds bin/sekurircd and bin/services
tools/makeconf.py     # answer a few questions: writes config/sekurircd.toml and services/services.toml
./sekurircd start     # starts both daemons (also: stop, restart, status)
```

Then connect any IRC client to your server on port `6667` (plain), or `6697` if you turned TLS on.
Prefer a browser? The [config wizard](https://gcanosa.github.io/SekurIRCd/docs/wizard.html) builds the same files online.

Running it as a service, upgrading, and every option are in the [install guide](https://gcanosa.github.io/SekurIRCd/docs/install.html).

## What's in the box

| | |
|---|---|
| `bin/sekurircd` | the IRC server |
| `bin/services` | NickServ + ChanServ, one process for the whole network |
| `web/` | the project website and the browser chat client |
| `stats/` | the optional stats dashboard |
| `tools/` | the config wizard, link manager, config checker and upgrader |
| `config/` | documented config templates (your live copies are never overwritten) |

## Documentation

| | |
|---|---|
| [Install](https://gcanosa.github.io/SekurIRCd/docs/install.html) | build, daemon mode, systemd, upgrading |
| [Configuration](https://gcanosa.github.io/SekurIRCd/docs/configuration.html) | every section of `sekurircd.toml`, operators, TLS, linking servers |
| [Config wizard](https://gcanosa.github.io/SekurIRCd/docs/wizard.html) | build a ready config in your browser |
| [Commands & modes](https://gcanosa.github.io/SekurIRCd/docs/commands.html) | user and operator commands, channel and user modes |
| [IRCv3 & SASL](https://gcanosa.github.io/SekurIRCd/docs/ircv3.html) | capabilities, accounts, SASL PLAIN and EXTERNAL |
| [Services](https://gcanosa.github.io/SekurIRCd/docs/chanserv.html) | NickServ and ChanServ |
| [Protection bundle](https://gcanosa.github.io/SekurIRCd/docs/protection.html) | DNSBL, proxy scanner, connection limits |
| [Stats panel](https://gcanosa.github.io/SekurIRCd/docs/stats.html) | the admin dashboard |
| [Web chat](https://gcanosa.github.io/SekurIRCd/docs/webchat.html) | the browser client |
| [Changelog](https://gcanosa.github.io/SekurIRCd/changelog.html) | what changed in each release |

## Support & community

- Join **`irc.sekurnet.org`** (port `6667` plain, `6697` TLS) and ask in **`#SekurNet`**, the project's support
  channel, run on SekurIRCd itself.
- **SekurNet** is the IRC network that uses and sponsors SekurIRCd: <https://www.sekurnet.org>.

## Contributing

`make check` runs the unit tests and `python3 tests/itest/run.py` runs the integration suite, which starts real
servers. `make debug` builds an ASan + UBSan binary.

## License

[MIT](LICENSE)
