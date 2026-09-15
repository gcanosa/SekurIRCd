/* Ported from sekurircd/src/sekurircd/logging_setup.py: console (ANSI-colored
 * when stderr is a TTY and NO_COLOR isn't set) + optional size-rotated file
 * output. File output is always plain text. */
#ifndef SEKURIRCD_LOG_H
#define SEKURIRCD_LOG_H

#include <stddef.h>

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_CRITICAL,
} log_level_t;

typedef struct {
    int enabled;            /* file logging master switch */
    char directory[512];
    char file[256];
    int debug;               /* force DEBUG level regardless of `level` */
    log_level_t level;       /* effective minimum level when debug == 0 */
    long max_bytes;
    int backup_count;
} log_config_t;

/* (Re)configure logging -- same "clear every handler, rebuild" semantics as
 * setup_logging(): safe to call again on /REHASH. `verbose` mirrors --verbose
 * (forces DEBUG regardless of config, like Python's `verbose` param). */
void log_init(const log_config_t *cfg, int verbose);

/* Hook fed every WARNING+ line (message only, no timestamp/level prefix --
 * the debug channel relay in server.c adds its own framing), same role as
 * Server._DebugChannelLogHandler. NULL clears it. */
void log_set_hook(void (*hook)(log_level_t level, const char *tag, const char *msg));

void log_write(log_level_t level, const char *tag, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

#define log_debug(tag, ...)    log_write(LOG_DEBUG, tag, __VA_ARGS__)
#define log_info(tag, ...)     log_write(LOG_INFO, tag, __VA_ARGS__)
#define log_warn(tag, ...)     log_write(LOG_WARNING, tag, __VA_ARGS__)
#define log_error(tag, ...)    log_write(LOG_ERROR, tag, __VA_ARGS__)
#define log_critical(tag, ...) log_write(LOG_CRITICAL, tag, __VA_ARGS__)

/* Parse "DEBUG"/"INFO"/.../"CRITICAL" (case-insensitive); returns LOG_INFO
 * for an unrecognized name (config.c validates the string itself, this is
 * just the enum conversion). */
log_level_t log_level_from_name(const char *name);

#endif /* SEKURIRCD_LOG_H */
