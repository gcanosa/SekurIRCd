/* Assert-based self-check for proto.c/crypto.c/config.c -- `make check`.
 * No framework: each test is a function that asserts; main() runs them all
 * and prints "OK" on a clean exit. A failing assert aborts with a stack
 * trace, which is enough to find the break. */
#include "channel.h"
#include "client.h"
#include "cmd.h"
#include "config.h"
#include "crypto.h"
#include "log.h"
#include "net.h"
#include "proto.h"
#include "protection.h"
#include "server.h"
#include "spam.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void test_parse_basic(void) {
    char line[] = "FOO bar baz :trailing param here";
    irc_message_t m;
    assert(irc_parse_line(line, &m) == 0);
    assert(strcmp(m.command, "FOO") == 0);
    assert(m.nparams == 3);
    assert(strcmp(m.params[0], "bar") == 0);
    assert(strcmp(m.params[1], "baz") == 0);
    assert(strcmp(m.params[2], "trailing param here") == 0);
    assert(m.prefix == NULL);
    assert(m.ntags == 0);
}

static void test_parse_prefix_and_lowercase_command(void) {
    char line[] = ":nick!user@host privmsg #chan :hi there";
    irc_message_t m;
    assert(irc_parse_line(line, &m) == 0);
    assert(strcmp(m.prefix, "nick!user@host") == 0);
    assert(strcmp(m.command, "PRIVMSG") == 0); /* uppercased in place */
    assert(m.nparams == 2);
    assert(strcmp(m.params[0], "#chan") == 0);
    assert(strcmp(m.params[1], "hi there") == 0);
}

static void test_parse_tags(void) {
    char line[] = "@id=123;account=nick;standalone :nick PRIVMSG #c :hi";
    irc_message_t m;
    assert(irc_parse_line(line, &m) == 0);
    assert(m.ntags == 3);
    assert(strcmp(m.tags[0].key, "id") == 0 && strcmp(m.tags[0].val, "123") == 0);
    assert(strcmp(m.tags[1].key, "account") == 0 && strcmp(m.tags[1].val, "nick") == 0);
    assert(strcmp(m.tags[2].key, "standalone") == 0 && strcmp(m.tags[2].val, "") == 0);
    assert(strcmp(m.prefix, "nick") == 0);
    assert(strcmp(m.command, "PRIVMSG") == 0);
}

static void test_parse_tag_escapes(void) {
    /* \: -> ; , \s -> space, \\ -> \ */
    char line[] = "@note=a\\:b\\sc\\\\d PING";
    irc_message_t m;
    assert(irc_parse_line(line, &m) == 0);
    assert(strcmp(m.tags[0].val, "a;b c\\d") == 0);
}

static void test_parse_colon_in_middle_param_is_literal(void) {
    /* Only " :" (space-colon) starts trailing -- a bare ':' mid-token
     * (IPv6 literal, mode key, OPER password) is a literal character. */
    char line[] = "KLINE *!*@2001:db8::1 :spam";
    irc_message_t m;
    assert(irc_parse_line(line, &m) == 0);
    assert(m.nparams == 2);
    assert(strcmp(m.params[0], "*!*@2001:db8::1") == 0);
    assert(strcmp(m.params[1], "spam") == 0);
}

static void test_parse_rejects_empty_and_bare_prefix(void) {
    irc_message_t m;
    char e1[] = "";
    assert(irc_parse_line(e1, &m) == -1);
    char e2[] = ":onlyaprefix";
    assert(irc_parse_line(e2, &m) == -1);
    char e3[] = "@onlytags";
    assert(irc_parse_line(e3, &m) == -1);
}

static void test_parse_consecutive_spaces_filtered(void) {
    char line[] = "FOO   bar    baz";
    irc_message_t m;
    assert(irc_parse_line(line, &m) == 0);
    assert(m.nparams == 2); /* empty tokens from runs of spaces are dropped */
    assert(strcmp(m.params[0], "bar") == 0);
    assert(strcmp(m.params[1], "baz") == 0);
}

static void test_build_basic(void) {
    char out[512];
    const char *params[] = {"#chan"};
    int n = irc_build(out, sizeof out, NULL, 0, "nick!user@host", "PRIVMSG", params, 1, "hello world");
    assert(n > 0);
    assert(strcmp(out, ":nick!user@host PRIVMSG #chan :hello world") == 0);
}

static void test_build_strips_injection(void) {
    /* \r\n\0 in a param/trailing must never reach the wire -- this is the
     * line-injection invariant every handler downstream depends on. */
    char out[512];
    const char *params[] = {"evil\r\nQUIT :bye"};
    int n = irc_build(out, sizeof out, NULL, 0, NULL, "NOTICE", params, 1, "msg\r\nwith\ninjection");
    assert(n > 0);
    assert(strstr(out, "\r") == NULL);
    assert(strstr(out, "\n") == NULL);
}

static void test_build_tags(void) {
    char out[512];
    irc_tag_t tags[2] = {{"time", "2024-01-02T03:04:05.678Z"}, {"account", ""}};
    int n = irc_build(out, sizeof out, tags, 2, NULL, "PRIVMSG", NULL, 0, "hi");
    assert(n > 0);
    assert(strcmp(out, "@time=2024-01-02T03:04:05.678Z;account PRIVMSG :hi") == 0);
}

static void test_build_truncation_detected(void) {
    char out[8];
    const char *params[] = {"toolongtofit"};
    int n = irc_build(out, sizeof out, NULL, 0, NULL, "X", params, 1, NULL);
    assert(n == -1);
}

static void test_validators(void) {
    assert(irc_valid_nick("ethernet_", 30));
    assert(irc_valid_nick("[bracket]", 30));
    assert(irc_valid_nick("_leading", 30));
    assert(!irc_valid_nick("1startswithdigit", 30));
    assert(!irc_valid_nick("", 30));
    assert(!irc_valid_nick("way-too-long-a-nickname-for-the-limit", 10));

    assert(irc_valid_user("ident_ok-1", 30));
    assert(!irc_valid_user("-startswithdash", 30)); /* USER_RE: first char must be alnum/_, no leading '~' */

    assert(irc_valid_channel("#general", 50));
    assert(irc_valid_channel("#a", 50));
    assert(!irc_valid_channel("general", 50));   /* missing # */
    assert(!irc_valid_channel("#", 50));          /* body too short */

    assert(irc_valid_host("irc.example.com"));
    assert(irc_valid_host("2001:db8::1"));
    assert(!irc_valid_host("has space"));
}

static void test_casefold(void) {
    char out[64];
    irc_casefold(out, sizeof out, "ScrewedCase_Nick");
    assert(strcmp(out, "screwedcase_nick") == 0);
}

static void test_glob_and_masks(void) {
    assert(irc_glob_match("*!*@*.example.com", "nick!user@host.example.com"));
    assert(!irc_glob_match("*!*@*.example.com", "nick!user@other.com"));
    assert(irc_glob_match("a?c", "abc"));
    /* '[' and ']' are LITERAL, never an fnmatch character class -- a nick
     * legally containing brackets (e.g. "work[nick]") must ban/match as-is. */
    assert(irc_glob_match("work[nick]", "work[nick]"));
    assert(!irc_glob_match("work[nick]", "worknick")); /* not a char class */

    /* bare nick-only mask (no '!'/'@') */
    assert(irc_mask_match("Bob", "bob", "host.example", "bob", 0));
    assert(irc_mask_match("Bob", "bob", "host.example", "b*", 0));

    /* full nick!user@host mask; user gets a '~' prefix unless already present */
    assert(irc_mask_match("nick", "user", "host.example", "nick!~user@host.example", 0));
    assert(irc_mask_match("nick", "~user", "host.example", "nick!~user@host.example", 0));
    assert(!irc_mask_match("nick", "user", "host.example", "other!~user@host.example", 0));
    /* an identd-confirmed user has no tilde, so a ban written the way
     * WHOIS displays them must match -- and the tilde form must not. */
    assert(irc_mask_match("nick", "user", "host.example", "nick!user@host.example", 1));
    assert(!irc_mask_match("nick", "user", "host.example", "nick!~user@host.example", 1));

    /* host_mask_match: no bare-nick shortcut; missing '@' means "*@<mask>" */
    assert(irc_host_mask_match("ident", "203.0.113.42", "203.0.113.*"));
    assert(irc_host_mask_match("ident", "203.0.113.42", "*@203.0.113.42"));
    assert(!irc_host_mask_match("ident", "203.0.113.42", "204.*"));
}

/* Regression: a ban written against the real hostname or bare IP must still
 * catch a client whose *displayed* host is a random per-connection cloak
 * (host_masking) -- channel_is_banned used to check `host` alone. */
static void test_channel_ban_matches_realhost_and_ip(void) {
    channel_t *chan = channel_new("#test", "#test");
    assert(chan);
    assert(masklist_add(&chan->bans, "*!*@bad.example.com") == 0);

    /* displayed host is a cloak; ban is written against the real hostname */
    assert(channel_is_banned(chan, "nick", "user", "abcd1234.users.net", "bad.example.com", "198.51.100.7", "", 0));
    /* ban written against the bare IP still catches the cloaked display */
    channel_t *chan2 = channel_new("#test2", "#test2");
    assert(masklist_add(&chan2->bans, "*!*@198.51.100.7") == 0);
    assert(channel_is_banned(chan2, "nick", "user", "cloak.example.net", "real.example.net", "198.51.100.7", "", 0));
    /* none of the three match: not banned */
    assert(!channel_is_banned(chan2, "nick", "user", "cloak.example.net", "real.example.net", "203.0.113.99", "", 0));

    channel_free(chan);
    channel_free(chan2);
}

static void test_durations(void) {
    assert(irc_parse_duration("1d") == 86400);
    assert(irc_parse_duration("12h") == 12 * 3600);
    assert(irc_parse_duration("30m") == 30 * 60);
    assert(irc_parse_duration("45s") == 45);
    assert(irc_parse_duration("3600") == 3600); /* bare number = seconds */
    assert(irc_parse_duration("") == -1);
    assert(irc_parse_duration("abc") == -1);
    assert(irc_parse_duration("1x") == -1); /* unknown unit */
    assert(irc_parse_duration("1d2h") == -1); /* trailing garbage */
}

static void test_prefix_for(void) {
    char out[128];
    irc_prefix_for(out, sizeof out, "nick", "user", "host.example");
    assert(strcmp(out, "nick!~user@host.example") == 0);
    irc_prefix_for(out, sizeof out, "nick", "~user", "host.example");
    assert(strcmp(out, "nick!~user@host.example") == 0);
    irc_prefix_for(out, sizeof out, "nick", "", "host.example");
    assert(strcmp(out, "nick@host.example") == 0);
}

static void test_add_time_tag(void) {
    char line[256];
    snprintf(line, sizeof line, "%s", "PRIVMSG #chan :hi");
    irc_add_time_tag(line, sizeof line);
    assert(strncmp(line, "@time=", 6) == 0);
    assert(strstr(line, " PRIVMSG #chan :hi") != NULL);

    /* already has a time tag -> no-op */
    snprintf(line, sizeof line, "%s", "@time=already;foo=bar PRIVMSG #chan :hi");
    char before[256];
    snprintf(before, sizeof before, "%s", line);
    irc_add_time_tag(line, sizeof line);
    assert(strcmp(line, before) == 0);
}

/* --- crypto ----------------------------------------------------------------- */

static void test_scrypt_roundtrip(void) {
    char hash[256];
    assert(crypto_hash_password("correct horse battery staple", hash, sizeof hash) == 0);
    assert(strncmp(hash, "scrypt$16384$8$1$", 17) == 0);
    assert(crypto_verify_password("correct horse battery staple", hash) == 1);
    assert(crypto_verify_password("wrong password", hash) == 0);
    assert(crypto_verify_password("correct horse battery staple", "garbage$not$a$hash") == 0);
    assert(crypto_verify_password("correct horse battery staple", "") == 0);
}

/* Vector produced once by the Python daemon's own hashlib.scrypt (see
 * passwords.py) for password "hunter2" -- proves a config file's existing
 * password_hash (or accounts.json/chanserv.json pw_hash) keeps verifying
 * unchanged after migrating to this C port. */
static void test_scrypt_cross_compat_vector(void) {
    const char *stored =
        "scrypt$16384$8$1$d06390215212123025d912b3d1dd686d$"
        "144a5efc2b49be064c3cf1b6d6fd292c6047453d55833424ace93e2eb8304a8"
        "cc6f50cc4350ae0dd07a28464646c2c7e223852e1bc1eebb9497cd7ffab9535f1";
    assert(crypto_verify_password("hunter2", stored) == 1);
    assert(crypto_verify_password("not-hunter2", stored) == 0);
}

static void test_random_hex(void) {
    char a[32], b[32];
    crypto_random_hex(a, sizeof a, 8);
    crypto_random_hex(b, sizeof b, 8);
    assert(strlen(a) == 16);
    assert(strcmp(a, b) != 0); /* astronomically unlikely to collide */
}

/* --- config ------------------------------------------------------------------ */

static void test_config_defaults(void) {
    config_t cfg;
    config_defaults(&cfg);
    assert(strcmp(cfg.server.name, "sekuri") == 0);
    assert(cfg.server.port == 6667);
    assert(cfg.security.max_nick_length == 30);
    assert(cfg.security.n_reserved_nicks == 6);
    assert(cfg.logging.enabled == 1);
}

static void test_config_cloak_format(void) {
    char out[128];
    assert(config_format_cloak("{token}.users.{network}", "abcd1234", "sekurnet", out, sizeof out) == 0);
    assert(strcmp(out, "abcd1234.users.sekurnet") == 0);
    assert(config_format_cloak("{bogus}", "tok", "net", out, sizeof out) == -1);
}

static void test_config_load_missing_file(void) {
    config_t cfg;
    char err[256];
    assert(config_load("/nonexistent/path/sekurircd.toml", &cfg, err, sizeof err) == -1);
    assert(err[0] != '\0');
}

static void test_connect_flood_throttle(void) {
    cfg_security_t sec;
    memset(&sec, 0, sizeof sec);
    sec.connect_flood_max = 3;
    sec.connect_flood_window = 10.0;

    /* first 3 connects from the same IP within the window: not flooding yet */
    assert(net_connect_flood_hit(&sec, "203.0.113.9") == 0);
    assert(net_connect_flood_hit(&sec, "203.0.113.9") == 0);
    assert(net_connect_flood_hit(&sec, "203.0.113.9") == 0);
    /* 4th connect trips it */
    assert(net_connect_flood_hit(&sec, "203.0.113.9") == 1);
    /* stays tripped while still spamming within the window */
    assert(net_connect_flood_hit(&sec, "203.0.113.9") == 1);

    /* a different IP has its own independent counter */
    assert(net_connect_flood_hit(&sec, "203.0.113.10") == 0);

    /* Regression: two IPs alternating within the same second used to land on
     * the same `now % CONNECT_FLOOD_SLOTS` slot every time and evict each
     * other's counter on every call, so neither ever accumulated enough
     * count to trip -- new-IP eviction now picks the oldest/empty slot
     * instead, so each of these two keeps its own counter. */
    sec.connect_flood_max = 2;
    int tripped_a = 0, tripped_b = 0;
    for (int i = 0; i < 6; i++) {
        if (net_connect_flood_hit(&sec, "203.0.113.20")) tripped_a = 1;
        if (net_connect_flood_hit(&sec, "203.0.113.21")) tripped_b = 1;
    }
    assert(tripped_a && tripped_b);

    /* connect_flood_max <= 0 disables the check entirely */
    sec.connect_flood_max = 0;
    for (int i = 0; i < 10; i++) assert(net_connect_flood_hit(&sec, "203.0.113.11") == 0);
}

/* --- spam protection ---------------------------------------------------------- */

static void test_spam_config_defaults_and_template(void) {
    config_t cfg;
    config_defaults(&cfg);
    assert(cfg.spam.enabled == 0);
    assert(cfg.spam.max_targets == 5 && cfg.spam.new_user_period == 30);
    /* the shipped template must parse, with [spam] off */
    char err[256];
    assert(config_load("config/sekurircd.template.toml", &cfg, err, sizeof err) == 0);
    assert(cfg.spam.enabled == 0 && cfg.spam.filters_enabled == 1);
    assert(cfg.spam.target_window == 30 && cfg.spam.zline_duration == 3600);
    assert(strcmp(cfg.spam.limit_action, "block") == 0);
}

static void test_spam_track_limits(void) {
    client_t *cl = client_new(-1, NULL);
    assert(cl);
    int distinct, same;
    time_t t0 = 1000;
    /* same long text to 4 different targets: distinct grows, so does `same` */
    const char *tg[] = {"#a", "#b", "bob", "#c"};
    for (int i = 0; i < 4; i++) spam_track(cl, tg[i], "buy cheap stuff at my site", t0, 30, &distinct, &same);
    assert(distinct == 4 && same == 4);
    /* repeating the identical (target,text) pair doesn't add a recipient */
    spam_track(cl, "#a", "buy cheap stuff at my site", t0 + 1, 30, &distinct, &same);
    assert(distinct == 4 && same == 4);
    /* target names are case-insensitive */
    spam_track(cl, "#A", "buy cheap stuff at my site", t0 + 2, 30, &distinct, &same);
    assert(distinct == 4);
    /* different text to a new target: distinct 5, same-text stays 1 */
    spam_track(cl, "#d", "something else entirely", t0 + 3, 30, &distinct, &same);
    assert(distinct == 5 && same == 1);
    /* once the window has passed, old sends no longer count */
    spam_track(cl, "#e", "fresh", t0 + 100, 30, &distinct, &same);
    assert(distinct == 1 && same == 1);
    client_free(cl);
}

static void test_spam_filters_and_check(void) {
    config_t cfg;
    config_defaults(&cfg);
    cfg.spam.enabled = 1;
    cfg.spam.filters_file[0] = '\0'; /* memory-only rules */
    cfg.spam.new_user_period = 0;
    cfg.spam.max_targets = 4;
    cfg.spam.max_repeat = 0;
    server_t srv;
    assert(server_init(&srv, &cfg) == 0);
    client_t *cl = client_new(-1, &srv);
    cl->fd = 99; /* not a services pseudo-client; nothing is ever written to it */
    assert(cl);
    snprintf(cl->nick, sizeof cl->nick, "spammer");
    snprintf(cl->ip, sizeof cl->ip, "203.0.113.5");

    assert(spam_parse_targets("pcnN") == (SPAM_T_PRIVMSG_USER | SPAM_T_PRIVMSG_CHAN | SPAM_T_NOTICE_USER | SPAM_T_NOTICE_CHAN));
    assert(spam_parse_targets("px") == 0 && spam_parse_targets("") == 0);

    /* no rules yet: passes; then a live rule is added via the command path */
    assert(spam_check_message(&srv, cl, "#chan", "cheap VIAGRA here", 0) == 0);
    irc_message_t m;
    memset(&m, 0, sizeof m);
    const char *bad[] = {"ADD", "c", "block", "-", "ads", "\\1"};
    m.nparams = 6; for (int i = 0; i < 6; i++) m.params[i] = (char *)bad[i];
    cmd_spamfilter(&srv, cl, &m);
    assert(srv.spam_filters == NULL); /* backreference refused */
    const char *empty[] = {"ADD", "c", "block", "-", "ads", "x*"};
    for (int i = 0; i < 6; i++) m.params[i] = (char *)empty[i];
    cmd_spamfilter(&srv, cl, &m);
    assert(srv.spam_filters == NULL); /* matches the empty string: refused */
    const char *good[] = {"ADD", "c", "block", "-", "ads", "(cheap|free) +viagra"};
    for (int i = 0; i < 6; i++) m.params[i] = (char *)good[i];
    cmd_spamfilter(&srv, cl, &m);
    assert(srv.spam_filters != NULL);

    /* matches through colour codes and case; channel rule doesn't hit a PM */
    assert(spam_check_message(&srv, cl, "#chan", "CHEAP \x02\x03""4VIAGRA here", 0) == 1);
    assert(spam_check_message(&srv, cl, "@#chan", "just chatting", 0) == 0);
    assert(spam_check_message(&srv, cl, "#chan", "free viagra", 1) == 0); /* rule is PRIVMSG-only */

    /* recipient limit (4; #chan already counts as one): #x1-#x3 ok, #x4 blocked */
    assert(spam_check_message(&srv, cl, "#x1", "hello there", 0) == 0);
    assert(spam_check_message(&srv, cl, "#x2", "hello there", 0) == 0);
    assert(spam_check_message(&srv, cl, "#x3", "hello there", 0) == 0);
    assert(spam_check_message(&srv, cl, "#x4", "hello there", 0) == 1);

    /* exempt: an identified account whose registration predates
     * new_user_period skips everything (accounts_created_at must actually
     * find a real account -- a bare cl->account with nothing registered
     * behind it, or one too fresh, is NOT exempt: see spam_check_message's
     * trusted_account gate, closing the instant-/REGISTER spam bypass). */
    accounts_register_hashed(&srv.accounts, "bob", "unused-in-this-test");
    snprintf(cl->account, sizeof cl->account, "bob");
    assert(spam_check_message(&srv, cl, "#chan", "free viagra", 0) == 0);

    /* the "fresh connection can't PM users" gate: "bob" registered moments
     * ago, not yet trusted -- still blocked, same as an account that was
     * never registered at all, or no account. */
    srv.cfg.spam.new_user_period = 3600;
    assert(spam_check_message(&srv, cl, "somebody", "hi", 0) == 1);
    snprintf(cl->account, sizeof cl->account, "nosuchaccount");
    assert(spam_check_message(&srv, cl, "somebody", "hi", 0) == 1);
    cl->account[0] = '\0';
    assert(spam_check_message(&srv, cl, "somebody", "hi", 0) == 1);
    srv.cfg.spam.new_user_period = 0;

    /* master switch off = inert */
    srv.cfg.spam.enabled = 0;
    assert(spam_check_message(&srv, cl, "#chan", "free viagra", 0) == 0);
    srv.cfg.spam.enabled = 1;

    /* zline action disconnects and lists a Z-line for the IP */
    const char *zl[] = {"ADD", "c", "zline", "1h", "bot", "botnet-advert"};
    for (int i = 0; i < 6; i++) m.params[i] = (char *)zl[i];
    cmd_spamfilter(&srv, cl, &m);
    /* rule order: first (viagra) wins, so use a text that only the new rule hits */
    assert(spam_check_message(&srv, cl, "#chan", "BOTNET-ADVERT now", 0) == 1);
    assert(cl->quitting == 1);
    assert(server_kline_match(&srv, "203.0.113.5", "u", "h", 0) != NULL);

    spam_free(&srv);
    assert(srv.spam_filters == NULL);
    cl->fd = -1;
    client_free(cl);
}

static void test_proc_stats(void) {
    double cpu = -1;
    long rss = -1;
    assert(proc_stats(getpid(), &cpu, &rss) == 0);
    assert(rss > 0);
    assert(cpu >= 0);
    /* a pid this large is never a live process */
    assert(proc_stats((pid_t)999999, &cpu, &rss) == -1);
}


/* Regression for the MODE stack overflow: cmd_apply_channel_mode's bounds
 * guard used to sit at the BOTTOM of its loop, and the argument-free-flag
 * branch ended in `continue`, jumping straight over it. "MODE #c +nnnn..."
 * with a few hundred letters then wrote every one of them into a 64-byte
 * stack array -- reachable by any channel operator, and creating a channel
 * makes you one. */
static void test_channel_mode_string_cannot_overflow(void) {
    log_config_t lcfg = {0};
    lcfg.enabled = 0;
    lcfg.level = LOG_CRITICAL; /* keep the handler's log_info off stderr */
    log_init(&lcfg, 0);

    server_t srv;
    memset(&srv, 0, sizeof srv);
    config_defaults(&srv.cfg);

    /* fd 1 is never written to here: client_send only appends to sbuf. */
    client_t *cl = client_new(1, &srv);
    assert(cl != NULL);
    snprintf(cl->nick, sizeof cl->nick, "op");
    snprintf(cl->user, sizeof cl->user, "u");
    snprintf(cl->host, sizeof cl->host, "h");

    channel_t *chan = channel_new("#c", "#c");
    assert(chan != NULL);
    member_t *m = channel_add_member(chan, cl);
    assert(m != NULL);
    m->rank = RANK_OP;

    char modes[602];
    modes[0] = '+';
    memset(modes + 1, 'n', 600);
    modes[601] = '\0';
    cmd_apply_channel_mode(&srv, cl, chan, modes, NULL, 0, 1);

    /* The mode itself still applies; what it emits stays one sane MODE line
     * rather than hundreds of repeated letters. */
    assert(chan->modes & CMODE_N);
    assert(cl->sbuf_len > 0);
    assert(cl->sbuf_len < 200);

    /* Alternating signs exercise the same guard from the other direction. */
    for (size_t i = 0; i < sizeof modes - 1; i++) modes[i] = (i % 2) ? 'n' : '-';
    modes[sizeof modes - 1] = '\0';
    cl->sbuf_len = 0;
    cmd_apply_channel_mode(&srv, cl, chan, modes, NULL, 0, 1);
    assert(cl->sbuf_len < 200);

    channel_free(chan);
    client_free(cl);
}

/* K and G match user@host as well as the IP; Z stays IP-only because it is
 * applied at accept(), before any user/host exists. */
static void test_line_mask_hits(void) {
    assert(server_line_mask_hits("203.0.113.*", "Z", "203.0.113.7", "bob", "host.example", 0));
    assert(!server_line_mask_hits("*.example", "Z", "203.0.113.7", "bob", "host.example", 0));

    assert(server_line_mask_hits("203.0.113.*", "K", "203.0.113.7", "bob", "host.example", 0));
    assert(server_line_mask_hits("*.example", "K", "203.0.113.7", "bob", "host.example", 0));
    /* both ident spellings, so an oper needn't know whether identd answered */
    assert(server_line_mask_hits("~bob@host.example", "K", "203.0.113.7", "bob", "host.example", 0));
    assert(server_line_mask_hits("bob@host.example", "K", "203.0.113.7", "bob", "host.example", 1));
    assert(!server_line_mask_hits("*.other", "K", "203.0.113.7", "bob", "host.example", 0));
}

/* Tiny runner: the old main() printed a hardcoded "0 assertions across 24
 * tests" regardless of what actually ran, which is worse than no count. */
static int g_tests_run;

/* --- Protection bundle ------------------------------------------------------ */

static void test_protection_pure_helpers(void) {
    assert(protection_find((const unsigned char *)"abc\0def", 7, "def") == 4); /* binary-safe past a NUL */
    assert(protection_find((const unsigned char *)"abc", 3, "abcd") == -1);
    assert(protection_find((const unsigned char *)"abc", 3, "") == -1);

    char out[64];
    protection_expand("%i listed in %t (%r) 100%%", "1.2.3.4", "zone.example", "drone", out, sizeof out);
    assert(strcmp(out, "1.2.3.4 listed in zone.example (drone) 100%") == 0);
    protection_expand("port %p %z", "1.2.3.4", "socks5", "1080", out, sizeof out);
    assert(strcmp(out, "port 1080 %z") == 0); /* unknown escapes pass through */
    protection_expand("%i%i%i%i%i%i%i%i%i%i", "255.255.255.255", "", "", out, 20);
    assert(strlen(out) == 19); /* truncates, always terminates */

    unsigned char b[512];
    size_t n = protection_probe_bytes(SCAN_SOCKS4, "1.2.3.4", 6667, 0, b, sizeof b);
    static const unsigned char s4[] = {4, 1, 0x1a, 0x0b, 1, 2, 3, 4, 0};
    assert(n == sizeof s4 && memcmp(b, s4, n) == 0);
    n = protection_probe_bytes(SCAN_SOCKS5, "1.2.3.4", 6667, 0, b, sizeof b);
    static const unsigned char s5a[] = {5, 1, 0};
    assert(n == 3 && memcmp(b, s5a, n) == 0);
    n = protection_probe_bytes(SCAN_SOCKS5, "1.2.3.4", 6667, 1, b, sizeof b);
    static const unsigned char s5b[] = {5, 1, 0, 1, 1, 2, 3, 4, 0x1a, 0x0b};
    assert(n == sizeof s5b && memcmp(b, s5b, n) == 0);
    n = protection_probe_bytes(SCAN_HTTP, "1.2.3.4", 6667, 0, b, sizeof b);
    assert(n && strncmp((char *)b, "CONNECT 1.2.3.4:6667 HTTP/1.0\r\n\r\n", n) == 0 && n == 33);
    n = protection_probe_bytes(SCAN_HTTPPOST, "1.2.3.4", 6667, 0, b, sizeof b);
    assert(n && strncmp((char *)b, "POST http://1.2.3.4:6667/ HTTP/1.0\r\n", 36) == 0);
    assert(protection_probe_bytes(SCAN_HTTP, "not-an-ip", 1, 0, b, sizeof b) == 0);

    assert(config_scan_proto_parse("SOCKS5") == SCAN_SOCKS5 && config_scan_proto_parse("http") == SCAN_HTTP);
    assert(config_scan_proto_parse("gopher") == 0);
}

static void test_protection_bl_match(void) {
    cfg_protection_t p;
    memset(&p, 0, sizeof p);
    p.n_blacklists = 3;
    /* zone 0: exact codes, unknown listings NOT banned */
    snprintf(p.blacklists[0].zone, CFG_STR, "a.example");
    p.blacklists[0].n_replies = 2;
    p.blacklists[0].replies[0].code = 1; snprintf(p.blacklists[0].replies[0].text, CFG_STR, "open proxy");
    p.blacklists[0].replies[1].code = 5; snprintf(p.blacklists[0].replies[1].text, CFG_STR, "drone");
    /* zone 1: bitmask */
    snprintf(p.blacklists[1].zone, CFG_STR, "b.example");
    p.blacklists[1].bitmask = 1;
    p.blacklists[1].n_replies = 1;
    p.blacklists[1].replies[0].code = 4; snprintf(p.blacklists[1].replies[0].text, CFG_STR, "exploit");
    /* zone 2: no reply rules -- any listing bans */
    snprintf(p.blacklists[2].zone, CFG_STR, "c.example");

    char text[64];
    int codes[3] = {-1, -1, -1};
    assert(protection_bl_match(&p, codes, 3, text, sizeof text) == -1);      /* nothing listed */
    codes[0] = 5;
    assert(protection_bl_match(&p, codes, 3, text, sizeof text) == 0 && strcmp(text, "drone") == 0);
    codes[0] = 9;                                                            /* listed, unknown code, ban_unknown=0 */
    assert(protection_bl_match(&p, codes, 3, text, sizeof text) == -1);
    p.blacklists[0].ban_unknown = 1;
    assert(protection_bl_match(&p, codes, 3, text, sizeof text) == 0 && strcmp(text, "reply 9") == 0);
    codes[0] = -1; codes[1] = 6;                                             /* 6 = 4|2: the exploit bit is set */
    assert(protection_bl_match(&p, codes, 3, text, sizeof text) == 1 && strcmp(text, "exploit") == 0);
    codes[1] = 3;                                                            /* 3 = 2|1: no exploit bit */
    assert(protection_bl_match(&p, codes, 3, text, sizeof text) == -1);
    codes[2] = 2;
    assert(protection_bl_match(&p, codes, 3, text, sizeof text) == 2);

    p.n_exempt = 1;
    snprintf(p.exempt[0], CFG_MASK, "10.*");
    assert(protection_exempt(&p, "10.1.2.3") && !protection_exempt(&p, "11.1.2.3"));
}

static void write_file(const char *dir, const char *name, const char *body) {
    char path[512];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "w");
    assert(f);
    fputs(body, f);
    fclose(f);
}

static void test_protection_bundle_config(void) {
    char dir[64];
    snprintf(dir, sizeof dir, "/tmp/sekurircd-prot-%d", (int)getpid());
    assert(mkdir(dir, 0700) == 0);
    char main_path[600], err[512], cwd[400];
    snprintf(main_path, sizeof main_path, "%s/sekurircd.toml", dir);
    config_t cfg;

    /* No bundle file: legacy keys and [dnsbl] carry on, [dnsbl] is adapted. */
    write_file(dir, "sekurircd.toml",
               "[security]\nmax_connections_per_ip = 7\n[dnsbl]\nenabled = true\nzones = [\"z.example\"]\n"
               "action = \"kline\"\nkline_duration = \"2h\"\nlookup_url = \"https://x/?ip={ip}\"\n");
    assert(config_load(main_path, &cfg, err, sizeof err) == 0);
    assert(!cfg.protection.loaded && cfg.security.max_connections_per_ip == 7);
    assert(cfg.protection.n_blacklists == 1 && cfg.protection.bl_legacy && cfg.protection.bl_enabled);
    assert(strcmp(cfg.protection.bl_action, "zline") == 0 && strcmp(cfg.protection.bl_ban_duration, "2h") == 0);
    assert(strstr(cfg.protection.blacklists[0].reason, "https://x/?ip=%i") != NULL);
    assert(!cfg.protection.scan_enabled);

    /* Bundle present: it overlays only the keys it sets. */
    write_file(dir, "protection.toml",
               "[connection]\nmax_connections = 9\n[flood]\nmax_msgs = 3\n"
               "[spam]\nenabled = true\nmax_repeat = 2\n[exempt]\nips = [\"10.*\"]\n");
    assert(config_load(main_path, &cfg, err, sizeof err) == 0);
    assert(cfg.protection.loaded && cfg.security.max_connections == 9);
    assert(cfg.security.max_connections_per_ip == 7);           /* untouched: file didn't set it */
    assert(cfg.security.flood_max_msgs == 3 && cfg.security.flood_window == 1.0);
    assert(cfg.spam.enabled == 1 && cfg.spam.max_repeat == 2 && cfg.spam.max_targets == 5);
    assert(cfg.protection.n_exempt == 1);
    assert(cfg.protection.n_blacklists == 1 && cfg.protection.bl_legacy); /* no [blacklist]: legacy zones stay */

    /* An explicit [blacklist] wins over [dnsbl], and an explicit off stays off. */
    write_file(dir, "protection.toml", "[blacklist]\nenabled = false\n");
    assert(config_load(main_path, &cfg, err, sizeof err) == 0);
    assert(!cfg.protection.bl_enabled);

    /* Validation: each names the offending key. */
    write_file(dir, "protection.toml", "[scanner]\nenabled = true\nprotocols = [\"socks5:1080\"]\n");
    assert(config_load(main_path, &cfg, err, sizeof err) != 0 && strstr(err, "scanner.target.ip"));
    write_file(dir, "protection.toml", "[scanner]\nprotocols = [\"gopher:70\"]\n");
    assert(config_load(main_path, &cfg, err, sizeof err) != 0 && strstr(err, "scanner.protocols"));
    write_file(dir, "protection.toml", "[scanner]\nprotocols = [\"socks5:99999\"]\n");
    assert(config_load(main_path, &cfg, err, sizeof err) != 0);
    write_file(dir, "protection.toml", "[scanner]\naction = \"nuke\"\n");
    assert(config_load(main_path, &cfg, err, sizeof err) != 0 && strstr(err, "scanner.action"));
    write_file(dir, "protection.toml", "[[blacklist.zone]]\nname = \"z\"\ntype = \"weird\"\n");
    assert(config_load(main_path, &cfg, err, sizeof err) != 0 && strstr(err, "blacklist.zone.type"));
    write_file(dir, "protection.toml", "[[blacklist.zone]]\nname = \"z\"\nreplies = [\"nocolon\"]\n");
    assert(config_load(main_path, &cfg, err, sizeof err) != 0 && strstr(err, "replies"));
    write_file(dir, "protection.toml", "[flood]\nmax_msgs = 0\n");
    assert(config_load(main_path, &cfg, err, sizeof err) != 0 && strstr(err, "flood.max_msgs"));
    write_file(dir, "protection.toml", "this is = = not toml\n");
    assert(config_load(main_path, &cfg, err, sizeof err) != 0 && strstr(err, "protection.toml"));

    /* A complete scanner config parses, with the built-in target strings. */
    write_file(dir, "protection.toml",
               "[scanner]\nenabled = true\nnegcache = \"1h\"\nprotocols = [\"http:8080\", \"SOCKS4:1080\", \"socks5:1080\"]\n"
               "[scanner.target]\nip = \"203.0.113.10\"\nport = 6668\n");
    assert(config_load(main_path, &cfg, err, sizeof err) == 0);
    assert(cfg.protection.scan_enabled && cfg.protection.n_protocols == 3 && cfg.protection.scan_negcache == 3600);
    assert(cfg.protection.protocols[1].type == SCAN_SOCKS4 && cfg.protection.protocols[1].port == 1080);
    assert(cfg.protection.target_port == 6668 && cfg.protection.n_target_strings == 3);
    assert(strstr(cfg.protection.target_strings[0], "Looking up your hostname"));

    /* protection_file = "" never looks for one. */
    write_file(dir, "sekurircd.toml", "[security]\nprotection_file = \"\"\n");
    assert(config_load(main_path, &cfg, err, sizeof err) == 0 && !cfg.protection.loaded);

    /* The shipped template must parse as a bundle file, safely off/inert. */
    assert(getcwd(cwd, sizeof cwd));
    char body[900];
    snprintf(body, sizeof body, "[security]\nprotection_file = \"%s/config/protection.template.toml\"\n", cwd);
    write_file(dir, "sekurircd.toml", body);
    assert(config_load(main_path, &cfg, err, sizeof err) == 0);
    assert(cfg.protection.loaded && !cfg.protection.scan_enabled && !cfg.protection.bl_legacy);
    assert(cfg.protection.bl_enabled && cfg.protection.n_blacklists == 1);
    assert(strcmp(cfg.protection.blacklists[0].zone, "rbl.efnetrbl.org") == 0 && cfg.protection.blacklists[0].n_replies == 5);
    assert(cfg.protection.n_protocols >= 4 && cfg.protection.n_exempt == 1);
    assert(strcmp(cfg.security.connect_flood_kline_duration, "10m") == 0 && cfg.spam.enabled == 0);

    /* ...and so must the main template, which no longer carries those sections. */
    write_file(dir, "sekurircd.toml", "");
    snprintf(body, sizeof body, "cp config/sekurircd.template.toml %s/sekurircd.toml", dir);
    assert(system(body) == 0);
    assert(config_load(main_path, &cfg, err, sizeof err) == 0);
    assert(!cfg.dnsbl.enabled && !cfg.protection.bl_legacy);

    snprintf(body, sizeof body, "rm -rf %s", dir);
    assert(system(body) == 0);
}

#define RUN(t) do { t(); g_tests_run++; } while (0)

int main(void) {
    RUN(test_parse_basic);
    RUN(test_parse_prefix_and_lowercase_command);
    RUN(test_parse_tags);
    RUN(test_parse_tag_escapes);
    RUN(test_parse_colon_in_middle_param_is_literal);
    RUN(test_parse_rejects_empty_and_bare_prefix);
    RUN(test_parse_consecutive_spaces_filtered);
    RUN(test_build_basic);
    RUN(test_build_strips_injection);
    RUN(test_build_tags);
    RUN(test_build_truncation_detected);
    RUN(test_validators);
    RUN(test_casefold);
    RUN(test_glob_and_masks);
    RUN(test_channel_ban_matches_realhost_and_ip);
    RUN(test_durations);
    RUN(test_prefix_for);
    RUN(test_add_time_tag);
    RUN(test_scrypt_roundtrip);
    RUN(test_scrypt_cross_compat_vector);
    RUN(test_random_hex);
    RUN(test_config_defaults);
    RUN(test_config_cloak_format);
    RUN(test_config_load_missing_file);
    RUN(test_connect_flood_throttle);
    RUN(test_channel_mode_string_cannot_overflow);
    RUN(test_line_mask_hits);
    RUN(test_spam_config_defaults_and_template);
    RUN(test_spam_track_limits);
    RUN(test_spam_filters_and_check);
    RUN(test_proc_stats);
    RUN(test_protection_pure_helpers);
    RUN(test_protection_bl_match);
    RUN(test_protection_bundle_config);
    printf("OK (%d tests)\n", g_tests_run);
    return 0;
}
