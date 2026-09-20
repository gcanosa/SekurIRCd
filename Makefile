# SekurIRCd (C port) -- plain make, no build-system dependency.
#
# Targets:
#   make            release build -> bin/sekurircd
#   make debug      ASan+UBSan build -> bin/sekurircd-debug
#   make check      build + run tests/unit.c
#   make clean

CC       ?= cc
SRC_DIR  := src
VEND_DIR := src/vendor
BIN_DIR  := bin
OBJ_DIR  := build

# OpenSSL: try pkg-config first, fall back to common Homebrew prefixes (macOS
# doesn't ship dev headers for its system OpenSSL), then plain -lssl -lcrypto
# for a normal Linux install.
PKG_OPENSSL := $(shell pkg-config --exists openssl 2>/dev/null && echo yes)
ifeq ($(PKG_OPENSSL),yes)
  OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl)
  OPENSSL_LIBS   := $(shell pkg-config --libs openssl)
else
  BREW_OPENSSL := $(firstword $(wildcard /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3))
  ifneq ($(BREW_OPENSSL),)
    OPENSSL_CFLAGS := -I$(BREW_OPENSSL)/include
    OPENSSL_LIBS   := -L$(BREW_OPENSSL)/lib -lssl -lcrypto
  else
    OPENSSL_CFLAGS :=
    OPENSSL_LIBS   := -lssl -lcrypto
  endif
endif

# -Wno-format-truncation: most hits are operator-trusted config strings
# (server name, DNSBL URL, uplink name, ...) declared CFG_STR (256) snprintf'd
# into smaller display buffers; snprintf always null-terminates safely, so
# the worst case is a cosmetically truncated message, never a memory bug.
WARN     := -Wall -Wextra -Wno-unused-parameter -Wno-format-truncation
# -MMD -MP: emit a .d dependency file per .o listing the headers it included,
# so editing a .h (e.g. adding a struct field) correctly triggers a rebuild
# of every .c that includes it -- without this, `make` only looks at .c
# mtimes and happily links stale .o files compiled against an old struct
# layout, which corrupts memory in ways that are miserable to debug.
# Hardening. This daemon parses untrusted input on every socket, so the
# usual defaults are worth the handful of cycles:
#   -fstack-protector-strong  turns a stack-buffer overflow into a clean abort
#                             instead of controlled corruption
#   -D_FORTIFY_SOURCE=2       compile-time + runtime checks on the str*/mem*
#                             family (needs an optimizing build, hence -O2)
#   -Wformat-security         catches a non-literal format string
#   -Wvla                     there are no variable-length arrays here; keep it that way
# RELRO/BIND_NOW/noexecstack and -pie are GNU-ld spellings; macOS links PIE by
# default and its ld rejects -z, so they're Linux-only.
UNAME_S := $(shell uname -s)
HARDEN_CFLAGS  := -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 \
                  -Wformat -Wformat-security -Wvla
HARDEN_LDFLAGS :=
ifeq ($(UNAME_S),Linux)
  HARDEN_CFLAGS  += -fPIE
  HARDEN_LDFLAGS += -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack
endif

CFLAGS   ?= -std=c11 -O2 -g $(WARN) $(HARDEN_CFLAGS) -MMD -MP
# _POSIX_C_SOURCE: glibc hides strtok_r/localtime_r/struct sigaction under
# -std=c11 (strict ISO) unless a POSIX feature-test macro is defined; macOS's
# libc exposes them regardless, so this was silently missing before.
CPPFLAGS := -I$(SRC_DIR) -I$(VEND_DIR) -D_POSIX_C_SOURCE=200809L $(OPENSSL_CFLAGS)
LDFLAGS  ?= $(HARDEN_LDFLAGS)
LDLIBS   := $(OPENSSL_LIBS) -lpthread

CORE_SRCS := $(SRC_DIR)/proto.c $(SRC_DIR)/crypto.c $(SRC_DIR)/log.c $(SRC_DIR)/config.c \
             $(SRC_DIR)/channel.c $(SRC_DIR)/client.c $(SRC_DIR)/server.c $(SRC_DIR)/net.c \
             $(SRC_DIR)/link.c $(SRC_DIR)/accounts.c $(SRC_DIR)/worker.c \
             $(SRC_DIR)/cmd.c $(SRC_DIR)/cmd_reg.c $(SRC_DIR)/cmd_chan.c $(SRC_DIR)/cmd_user.c \
             $(SRC_DIR)/cmd_oper.c $(SRC_DIR)/cmd_info.c $(SRC_DIR)/spam.c $(SRC_DIR)/build.c
VEND_SRCS := $(VEND_DIR)/toml.c $(VEND_DIR)/cJSON.c
MAIN_SRC  := $(SRC_DIR)/main.c

ALL_SRCS  := $(CORE_SRCS) $(VEND_SRCS) $(MAIN_SRC)
ALL_OBJS  := $(patsubst %.c,$(OBJ_DIR)/%.o,$(ALL_SRCS))

# Build id for /VERSION: date + short commit (+ -dirty). build.o depends on
# every other object, so it is regenerated whenever anything else is.
BUILD_ID := $(shell date +%Y%m%d)-$(shell git rev-parse --short HEAD 2>/dev/null || echo release)$(shell git diff --quiet HEAD 2>/dev/null || echo -dirty)
$(OBJ_DIR)/$(SRC_DIR)/build.o: CPPFLAGS += -DSEKURIRCD_BUILD='"$(BUILD_ID)"'
$(OBJ_DIR)/$(SRC_DIR)/build.o: $(filter-out $(OBJ_DIR)/$(SRC_DIR)/build.o,$(ALL_OBJS))
build-debug/$(SRC_DIR)/build.o: CPPFLAGS += -DSEKURIRCD_BUILD='"$(BUILD_ID)-asan"'

.DEFAULT_GOAL := all
.PHONY: all debug check clean
all: $(BIN_DIR)/sekurircd $(BIN_DIR)/chanserv

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BIN_DIR)/sekurircd: $(ALL_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

debug: CFLAGS := -std=c11 -O0 -g $(WARN) -MMD -MP -fsanitize=address,undefined -fno-omit-frame-pointer
debug: LDFLAGS += -fsanitize=address,undefined
debug: OBJ_DIR := build-debug
debug: $(BIN_DIR)/sekurircd-debug

$(BIN_DIR)/sekurircd-debug: $(patsubst %.c,build-debug/%.o,$(ALL_SRCS))
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

build-debug/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

UNIT_SRCS := tests/unit.c $(CORE_SRCS) $(VEND_SRCS)
check: $(BIN_DIR)/unit
	./$(BIN_DIR)/unit

$(BIN_DIR)/unit: $(UNIT_SRCS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(UNIT_SRCS) $(LDLIBS)

CHANSERV_SRCS := services/chanserv.c $(SRC_DIR)/proto.c $(SRC_DIR)/crypto.c $(SRC_DIR)/log.c $(VEND_SRCS)
$(BIN_DIR)/chanserv: $(CHANSERV_SRCS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(CHANSERV_SRCS) $(LDLIBS)

clean:
	rm -rf $(OBJ_DIR) build-debug $(BIN_DIR)

# --- install / uninstall (Linux + systemd, no root/sudo) -------------------
#
# Fully rootless: everything lives under $HOME and units are systemd *user*
# units (systemctl --user ...), not system units -- no useradd, no /etc, no
# sudo anywhere in this recipe. sekurircd/chanserv never needed root anyway:
# their ports (6667/6697) are both >1024.
#
# Layout ($XDG_CONFIG_HOME/$XDG_STATE_HOME honored if set):
#   $(PREFIX)/bin/{sekurircd,chanserv}    -- binaries (default ~/.local/bin)
#   $(SYSCONFDIR)/                        -- config (default ~/.config/sekurircd;
#                                             [accounts] writes accounts.json here)
#   $(STATEDIR)/ircd/                     -- ircd WorkingDirectory (pidfile, logs/)
#   $(STATEDIR)/chanserv/                 -- chanserv WorkingDirectory (pidfile,
#                                             chanserv.json + rotating backups)
#                                             (default state dir ~/.local/state/sekurircd)
#   $(UNITDIR)/{sekurircd,chanserv}.service (default ~/.config/systemd/user)
#
# Only ships config/*.template.toml + ircd.motd -- never writes a live
# sekurircd.toml/services.toml itself (those need operator-chosen operators/
# secrets), matching the existing "cp *.template.toml" quick-start flow.
PREFIX     ?= $(HOME)/.local
SYSCONFDIR ?= $(shell echo "$${XDG_CONFIG_HOME:-$$HOME/.config}/sekurircd")
STATEDIR   ?= $(shell echo "$${XDG_STATE_HOME:-$$HOME/.local/state}/sekurircd")
UNITDIR    ?= $(shell echo "$${XDG_CONFIG_HOME:-$$HOME/.config}/systemd/user")

.PHONY: install uninstall
install: all
	@[ "$$(uname -s)" = Linux ] || { echo "make install: Linux + systemd only" >&2; exit 1; }
	install -d $(PREFIX)/bin
	install -m755 $(BIN_DIR)/sekurircd $(BIN_DIR)/chanserv $(PREFIX)/bin/
	install -d $(SYSCONFDIR) $(STATEDIR)/ircd/logs $(STATEDIR)/chanserv $(UNITDIR)
	sed -e 's|^chanserv_pidfile = ""|chanserv_pidfile = "$(STATEDIR)/chanserv/chanserv.pid"|' \
	    config/sekurircd.template.toml > $(SYSCONFDIR)/sekurircd.template.toml
	chmod 644 $(SYSCONFDIR)/sekurircd.template.toml
	install -m644 services/services.template.toml $(SYSCONFDIR)/
	test -f $(SYSCONFDIR)/ircd.motd || install -m644 config/ircd.motd $(SYSCONFDIR)/
	sed -e 's|/usr/local/bin|$(PREFIX)/bin|g' -e 's|/etc/sekurircd|$(SYSCONFDIR)|g' -e 's|/var/lib/sekurircd|$(STATEDIR)|g' \
	    systemd/sekurircd.service > $(UNITDIR)/sekurircd.service
	sed -e 's|/usr/local/bin|$(PREFIX)/bin|g' -e 's|/etc/sekurircd|$(SYSCONFDIR)|g' -e 's|/var/lib/sekurircd|$(STATEDIR)|g' \
	    systemd/chanserv.service > $(UNITDIR)/chanserv.service
	systemctl --user daemon-reload
	@echo "installed under $(PREFIX), $(SYSCONFDIR), $(STATEDIR)."
	@echo "next: cp $(SYSCONFDIR)/sekurircd.template.toml $(SYSCONFDIR)/sekurircd.toml (edit it), then:"
	@echo "  systemctl --user enable --now sekurircd chanserv"
	@echo "to keep running after logout / before login: loginctl enable-linger \$$(whoami)  (no sudo; may prompt for your own password)"

uninstall:
	@[ "$$(uname -s)" = Linux ] || { echo "make uninstall: Linux + systemd only" >&2; exit 1; }
	rm -f $(PREFIX)/bin/sekurircd $(PREFIX)/bin/chanserv
	rm -f $(UNITDIR)/sekurircd.service $(UNITDIR)/chanserv.service
	systemctl --user daemon-reload
	@echo "uninstalled binaries + unit files. left in place (remove by hand if you want):" \
	      "$(SYSCONFDIR), $(STATEDIR)"

-include $(ALL_OBJS:.o=.d)
-include $(patsubst %.c,build-debug/%.d,$(ALL_SRCS))
