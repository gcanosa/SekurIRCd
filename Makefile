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
CFLAGS   ?= -std=c11 -O2 -g $(WARN) -MMD -MP
# _POSIX_C_SOURCE: glibc hides strtok_r/localtime_r/struct sigaction under
# -std=c11 (strict ISO) unless a POSIX feature-test macro is defined; macOS's
# libc exposes them regardless, so this was silently missing before.
CPPFLAGS := -I$(SRC_DIR) -I$(VEND_DIR) -D_POSIX_C_SOURCE=200809L $(OPENSSL_CFLAGS)
LDFLAGS  ?=
LDLIBS   := $(OPENSSL_LIBS) -lpthread

CORE_SRCS := $(SRC_DIR)/proto.c $(SRC_DIR)/crypto.c $(SRC_DIR)/log.c $(SRC_DIR)/config.c \
             $(SRC_DIR)/channel.c $(SRC_DIR)/client.c $(SRC_DIR)/server.c $(SRC_DIR)/net.c \
             $(SRC_DIR)/link.c $(SRC_DIR)/accounts.c $(SRC_DIR)/worker.c \
             $(SRC_DIR)/cmd.c $(SRC_DIR)/cmd_reg.c $(SRC_DIR)/cmd_chan.c $(SRC_DIR)/cmd_user.c \
             $(SRC_DIR)/cmd_oper.c $(SRC_DIR)/cmd_info.c
VEND_SRCS := $(VEND_DIR)/toml.c $(VEND_DIR)/cJSON.c
MAIN_SRC  := $(SRC_DIR)/main.c

ALL_SRCS  := $(CORE_SRCS) $(VEND_SRCS) $(MAIN_SRC)
ALL_OBJS  := $(patsubst %.c,$(OBJ_DIR)/%.o,$(ALL_SRCS))

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

# --- install / uninstall (Linux + systemd only) ---------------------------
#
# Layout:
#   $(PREFIX)/bin/{sekurircd,chanserv}   -- binaries
#   /etc/sekurircd/                      -- config (owned by the service user:
#                                            [accounts] writes accounts.json here)
#   /var/lib/sekurircd/ircd/             -- ircd WorkingDirectory (pidfile, logs/)
#   /var/lib/sekurircd/chanserv/         -- chanserv WorkingDirectory (pidfile,
#                                            chanserv.json + rotating backups)
#   /etc/systemd/system/{sekurircd,chanserv}.service
#
# Only ships config/*.template.toml + ircd.motd -- never writes a live
# sekurircd.toml/services.toml itself (those need operator-chosen operators/
# secrets), matching the existing "cp *.template.toml" quick-start flow.
# DESTDIR is honored for staged/packaging installs (e.g. `make install
# DESTDIR=/pkg/root`), which skips chown/systemctl -- those only make sense
# against the real running system.
#
# Runs as the invoking user rather than a dedicated system account -- no
# useradd, no extra account to manage. `make install` is normally run via
# sudo, so SVCUSER prefers $SUDO_USER over `id -un` (which under sudo is
# root); override either on the command line if that guess is wrong.
PREFIX     ?= /usr/local
SYSCONFDIR ?= /etc/sekurircd
STATEDIR   ?= /var/lib/sekurircd
UNITDIR    ?= /etc/systemd/system
SVCUSER    ?= $(shell echo $${SUDO_USER:-$$(id -un)})
SVCGROUP   ?= $(shell id -gn $(SVCUSER) 2>/dev/null || echo $(SVCUSER))

.PHONY: install uninstall
install: all
	@[ "$$(uname -s)" = Linux ] || { echo "make install: Linux + systemd only" >&2; exit 1; }
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m755 $(BIN_DIR)/sekurircd $(BIN_DIR)/chanserv $(DESTDIR)$(PREFIX)/bin/
	install -d $(DESTDIR)$(SYSCONFDIR) $(DESTDIR)$(STATEDIR)/ircd/logs $(DESTDIR)$(STATEDIR)/chanserv
	install -m644 config/sekurircd.template.toml services/services.template.toml $(DESTDIR)$(SYSCONFDIR)/
	test -f $(DESTDIR)$(SYSCONFDIR)/ircd.motd || install -m644 config/ircd.motd $(DESTDIR)$(SYSCONFDIR)/
	install -d $(DESTDIR)$(UNITDIR)
	sed -e 's|/usr/local/bin|$(PREFIX)/bin|g' -e 's|^User=.*|User=$(SVCUSER)|' -e 's|^Group=.*|Group=$(SVCGROUP)|' \
	    systemd/sekurircd.service > $(DESTDIR)$(UNITDIR)/sekurircd.service
	sed -e 's|/usr/local/bin|$(PREFIX)/bin|g' -e 's|^User=.*|User=$(SVCUSER)|' -e 's|^Group=.*|Group=$(SVCGROUP)|' \
	    systemd/chanserv.service > $(DESTDIR)$(UNITDIR)/chanserv.service
	chmod 644 $(DESTDIR)$(UNITDIR)/sekurircd.service $(DESTDIR)$(UNITDIR)/chanserv.service
ifeq ($(DESTDIR),)
	chown -R $(SVCUSER):$(SVCGROUP) $(SYSCONFDIR) $(STATEDIR)
	systemctl daemon-reload
	@echo "installed (runs as $(SVCUSER):$(SVCGROUP)). next: edit $(SYSCONFDIR)/sekurircd.toml (copied from the .template.toml)," \
	      "then: systemctl enable --now sekurircd chanserv"
endif

uninstall:
	@[ "$$(uname -s)" = Linux ] || { echo "make uninstall: Linux + systemd only" >&2; exit 1; }
	rm -f $(DESTDIR)$(PREFIX)/bin/sekurircd $(DESTDIR)$(PREFIX)/bin/chanserv
	rm -f $(DESTDIR)$(UNITDIR)/sekurircd.service $(DESTDIR)$(UNITDIR)/chanserv.service
ifeq ($(DESTDIR),)
	systemctl daemon-reload
endif
	@echo "uninstalled binaries + unit files. left in place (remove by hand if you want):" \
	      "$(SYSCONFDIR), $(STATEDIR)"

-include $(ALL_OBJS:.o=.d)
-include $(patsubst %.c,build-debug/%.d,$(ALL_SRCS))
