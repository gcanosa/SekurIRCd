/* IRC wire protocol: line parsing, message building, validators, numerics.
 *
 * Ported from sekurircd/src/sekurircd/protocol.py -- see that file's
 * docstrings for the "why" behind each rule; this header only restates the
 * "what". No I/O, no state -- pure functions over caller-owned buffers.
 */
#ifndef SEKURIRCD_PROTO_H
#define SEKURIRCD_PROTO_H

#include <stddef.h>

#define IRC_MAX_PARAMS 32   /* generous; server.c enforces the configured max_params */
#define IRC_MAX_TAGS   32

typedef struct {
    const char *key;
    const char *val;   /* "" (not NULL) for a valueless tag, e.g. "@foo bar" */
} irc_tag_t;

/* A parsed message. All pointers point INTO the caller's mutable `line`
 * buffer (irc_parse_line rewrites it in place: '\0'-splits tokens, unescapes
 * tag values, uppercases the command) -- keep `line` alive as long as the
 * message is used, same lifetime rule as strtok. */
typedef struct {
    irc_tag_t tags[IRC_MAX_TAGS];
    int ntags;
    const char *prefix;              /* NULL if the line had none */
    char *command;                   /* uppercased in place */
    char *params[IRC_MAX_PARAMS];
    int nparams;
} irc_message_t;

/* Parse one line (CRLF already stripped). Mutates `line` in place and points
 * `msg` into it. Returns 0 on success, -1 for an empty line or one that is
 * only tags/a prefix with nothing after (mirrors protocol.parse_line
 * returning None). */
int irc_parse_line(char *line, irc_message_t *msg);

/* Build a wire line (no trailing CRLF) into `out` (size `outsz`).
 * `trailing` (may be NULL) is appended as the final ":"-prefixed param.
 * `tags`/`ntags` (may be NULL/0) are prepended as "@k=v;k2 ". Every prefix/
 * param/trailing value is escaped (irc_escape) so \r\n\0 can never be
 * injected. Returns the number of bytes written (excluding NUL), or -1 if
 * `out` was too small (line is left truncated/undefined-terminated -- callers
 * always size `out` to fit, this is a defensive check only). */
int irc_build(char *out, size_t outsz,
              const irc_tag_t *tags, int ntags,
              const char *prefix, const char *command,
              const char **params, int nparams,
              const char *trailing);

/* Strip \r, \n, \x00 from `in` into `out` (size outsz, NUL-terminated).
 * Returns the escaped length. */
size_t irc_escape(char *out, size_t outsz, const char *in);

/* --- validators ---------------------------------------------------------- */
int irc_valid_nick(const char *nick, int max_len);
int irc_valid_user(const char *user, int max_len);
int irc_valid_channel(const char *chan, int max_len);
int irc_valid_host(const char *host);

/* ASCII-casefold copy (IRC casemapping is ASCII-only in this daemon, same as
 * protocol.casefold's docstring) -- not full Unicode casefolding.
 * ponytail: ascii-only, matches upstream's own documented intent. */
void irc_casefold(char *out, size_t outsz, const char *in);

/* Case-insensitive glob match, '*'/'?' wildcards only -- every other
 * character (including '[' ']') is literal, which is the *result* of
 * protocol.py's fnmatch-bracket-escaping trick, done directly instead. */
int irc_glob_match(const char *pattern, const char *text);

/* nick!user@host banmask match. A mask with neither '!' nor '@' matches the
 * nick alone. */
int irc_mask_match(const char *nick, const char *user, const char *host, const char *mask);

/* user@host access-control match (VHOST/link peers) -- no bare-nick
 * shortcut; a mask with no '@' means "*@<mask>". */
int irc_host_mask_match(const char *user, const char *host, const char *mask);

/* Parse "1d"/"12h"/"30m"/"3600" into seconds. Returns -1 if not a duration
 * token at all (bare digits default to seconds). */
long irc_parse_duration(const char *token);

/* "nick!~user@host" (or "nick@host" if user is empty), written into out. */
void irc_prefix_for(char *out, size_t outsz, const char *nick, const char *user, const char *host);

/* Millisecond-precision UTC ISO8601 "2024-01-02T03:04:05.678Z" into out
 * (needs at least 25 bytes). */
void irc_iso8601_now(char *out, size_t outsz);

/* Insert a "time=<now>" tag into an already-built wire `line`, in place
 * (`line` must have room to grow by ~30 bytes -- pass a buffer, not a
 * literal). Merges into existing tags; a no-op if `line` already has a time
 * tag (never expected from our own code, same as protocol.add_time_tag). */
void irc_add_time_tag(char *line, size_t linesz);

/* --- IRCv3 capabilities (commands._CAP_ATTRS) ---------------------------- */
#define CAP_AWAY_NOTIFY       0x0001u
#define CAP_MULTI_PREFIX      0x0002u
#define CAP_USERHOST_IN_NAMES 0x0004u
#define CAP_SETNAME           0x0008u
#define CAP_CHGHOST           0x0010u
#define CAP_ACCOUNT_NOTIFY    0x0020u
#define CAP_EXTENDED_JOIN     0x0040u
#define CAP_ECHO_MESSAGE      0x0080u
#define CAP_MESSAGE_TAGS      0x0100u
#define CAP_SERVER_TIME       0x0200u
#define CAP_ACCOUNT_TAG       0x0400u
#define CAP_INVITE_NOTIFY     0x0800u
#define CAP_STANDARD_REPLIES  0x1000u

/* --- numeric reply codes (protocol.N) ------------------------------------ */
#define N_WELCOME          "001"
#define N_YOURHOST         "002"
#define N_CREATED          "003"
#define N_MYINFO           "004"
#define N_ISUPPORT         "005"
#define N_MAP              "006"
#define N_MAPEND           "007"

#define N_ADMINME          "256"
#define N_ADMINLOC1        "257"
#define N_ADMINLOC2        "258"
#define N_ADMINEMAIL       "259"

#define N_LUSERCLIENT      "251"
#define N_LUSEROP          "252"
#define N_LUSERUNKNOWN     "253"
#define N_LUSERCHANNELS    "254"
#define N_LUSERME          "255"
#define N_LOCALUSERS       "265"
#define N_GLOBALUSERS      "266"

#define N_STATSCOMMANDS    "212"
#define N_ENDOFSTATS       "219"
#define N_STATSCONN        "250"
#define N_STATSUPTIME      "242"
#define N_STATSOLINE       "243"

#define N_AWAY             "301"
#define N_USERHOST         "302"
#define N_ISON             "303"
#define N_UNAWAY           "305"
#define N_NOWAWAY          "306"

#define N_WHOISUSER        "311"
#define N_WHOISSERVER      "312"
#define N_WHOISOPERATOR    "313"
#define N_WHOWASUSER       "314"
#define N_ENDOFWHO         "315"
#define N_WHOISIDLE        "317"
#define N_ENDOFWHOIS       "318"
#define N_WHOISCHANNELS    "319"

#define N_LISTSTART        "321"
#define N_LIST             "322"
#define N_LISTEND          "323"
#define N_CHANNELMODEIS    "324"
#define N_CREATIONTIME     "329"
#define N_NOTOPIC          "331"
#define N_TOPIC            "332"
#define N_TOPICWHOTIME     "333"
#define N_INVITING         "341"

#define N_LINKS            "364"
#define N_ENDOFLINKS       "365"

#define N_VERSION          "351"
#define N_WHOREPLY         "352"
#define N_NAMEREPLY        "353"
#define N_ENDOFNAMES       "366"
#define N_BANLIST          "367"
#define N_ENDOFBANLIST     "368"
#define N_ENDOFWHOWAS      "369"

#define N_INVEXLIST        "346"
#define N_ENDOFINVEXLIST   "347"
#define N_EXCEPTLIST       "348"
#define N_ENDOFEXCEPTLIST  "349"

#define N_SILELIST         "271"
#define N_ENDOFSILELIST    "272"

#define N_INFO             "371"
#define N_MOTD             "372"
#define N_ENDOFINFO        "374"
#define N_MOTDSTART        "375"
#define N_ENDOFMOTD        "376"
#define N_WHOISHOST        "378"
#define N_WHOISSECURE      "671"
#define N_TIME             "391"

#define N_UMODEIS          "221"

#define N_YOUREOPER        "381"
#define N_REHASHING        "382"

#define N_HELPSTART        "704"
#define N_HELPTXT          "705"
#define N_ENDOFHELP        "706"
#define N_HELPNOTFOUND     "524"

#define N_KNOCK            "710"
#define N_KNOCKDLVR        "711"
#define N_CHANOPEN         "713"
#define N_KNOCKONCHAN      "714"

#define N_MONONLINE        "730"
#define N_MONOFFLINE       "731"
#define N_MONLIST          "732"
#define N_ENDOFMONLIST     "733"
#define N_MONLISTFULL      "734"

#define N_UNKNOWNERROR     "400"
#define N_NOSUCHNICK       "401"
#define N_NOSUCHSERVER     "402"
#define N_NOSUCHCHANNEL    "403"
#define N_CANNOTSENDTOCHAN "404"
#define N_TOOMANYCHANNELS  "405"
#define N_WASNOSUCHNICK    "406"
#define N_NORECIPIENT      "411"
#define N_NOTEXTTOSEND     "412"
#define N_INPUTTOOLONG     "417"
#define N_UNKNOWNCOMMAND   "421"
#define N_NOMOTD           "422"
#define N_NONICKNAMEGIVEN  "431"
#define N_ERRONEUSNICKNAME "432"
#define N_NICKNAMEINUSE    "433"
#define N_NICKCOLLISION    "436"
#define N_UNAVAILRESOURCE  "437"
#define N_USERNOTINCHANNEL "441"
#define N_NOTONCHANNEL     "442"
#define N_USERONCHANNEL    "443"
#define N_CANTCHANGENICK   "447"
#define N_NONONREG         "486"
#define N_NOTREGISTERED    "451"
#define N_NEEDMOREPARAMS   "461"
#define N_ALREADYREGISTERED "462"
#define N_PASSWDMISMATCH   "464"

#define N_CHANNELISFULL    "471"
#define N_UNKNOWNMODE      "472"
#define N_INVITEONLYCHAN   "473"
#define N_BANNED           "474"
#define N_NOCHANNELKEY     "475"
#define N_NOAVAIL          "476"
#define N_NOPRIVILEGES     "481"
#define N_CANTKILLSERVER   "483"
#define N_NOTCHANNELOP     "482"
#define N_SECUREONLYCHAN   "489"

#define N_NOOPERHOST       "491"

#define N_USERSDONTMATCH   "502"

#define N_YOURID           "042"
#define N_WHOISACCOUNT     "330"
#define N_TRACEOPERATOR    "204"
#define N_TRACEUSER        "205"
#define N_TRACESERVER      "206"
#define N_TRACEEND         "262"
#define N_SERVLIST         "234"
#define N_SERVLISTEND      "235"
#define N_WHOSPCRPL        "354"
#define N_LOGGEDIN         "900"
#define N_LOGGEDOUT        "901"
#define N_NICKLOCKED       "902"
#define N_SASLSUCCESS      "903"
#define N_SASLFAIL         "904"
#define N_SASLTOOLONG      "905"
#define N_SASLABORTED      "906"
#define N_SASLALREADY      "907"
#define N_SASLMECHS        "908"

#endif /* SEKURIRCD_PROTO_H */
