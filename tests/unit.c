/* Assert-based self-check for proto.c/crypto.c/config.c -- `make check`.
 * No framework: each test is a function that asserts; main() runs them all
 * and prints "OK" on a clean exit. A failing assert aborts with a stack
 * trace, which is enough to find the break. */
#include "config.h"
#include "crypto.h"
#include "net.h"
#include "proto.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
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
    assert(irc_mask_match("Bob", "bob", "host.example", "bob"));
    assert(irc_mask_match("Bob", "bob", "host.example", "b*"));

    /* full nick!user@host mask; user gets a '~' prefix unless already present */
    assert(irc_mask_match("nick", "user", "host.example", "nick!~user@host.example"));
    assert(irc_mask_match("nick", "~user", "host.example", "nick!~user@host.example"));
    assert(!irc_mask_match("nick", "user", "host.example", "other!~user@host.example"));

    /* host_mask_match: no bare-nick shortcut; missing '@' means "*@<mask>" */
    assert(irc_host_mask_match("ident", "203.0.113.42", "203.0.113.*"));
    assert(irc_host_mask_match("ident", "203.0.113.42", "*@203.0.113.42"));
    assert(!irc_host_mask_match("ident", "203.0.113.42", "204.*"));
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

static void test_proc_stats(void) {
    double cpu = -1;
    long rss = -1;
    assert(proc_stats(getpid(), &cpu, &rss) == 0);
    assert(rss > 0);
    assert(cpu >= 0);
    /* a pid this large is never a live process */
    assert(proc_stats((pid_t)999999, &cpu, &rss) == -1);
}

int main(void) {
    test_parse_basic();
    test_parse_prefix_and_lowercase_command();
    test_parse_tags();
    test_parse_tag_escapes();
    test_parse_colon_in_middle_param_is_literal();
    test_parse_rejects_empty_and_bare_prefix();
    test_parse_consecutive_spaces_filtered();
    test_build_basic();
    test_build_strips_injection();
    test_build_tags();
    test_build_truncation_detected();
    test_validators();
    test_casefold();
    test_glob_and_masks();
    test_durations();
    test_prefix_for();
    test_add_time_tag();
    test_scrypt_roundtrip();
    test_scrypt_cross_compat_vector();
    test_random_hex();
    test_config_defaults();
    test_config_cloak_format();
    test_config_load_missing_file();
    test_proc_stats();
    printf("OK (%d assertions across %d tests)\n", 0, 23);
    return 0;
}
