#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const char *LEVEL_NAME[] = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"};
/* Matches logging_setup.py's _LEVEL_COLORS (console only; files stay plain). */
static const char *LEVEL_COLOR[] = {
    "\033[90m",   /* gray */
    "\033[32m",   /* green */
    "\033[33m",   /* yellow */
    "\033[31m",   /* red */
    "\033[1;31m", /* bold red */
};
#define RESET "\033[0m"

static log_config_t g_cfg;
static log_level_t g_min_level = LOG_INFO;
static int g_use_color = 0;
static FILE *g_file = NULL;
static long g_file_size = 0;
static void (*g_hook)(log_level_t, const char *, const char *) = NULL;

log_level_t log_level_from_name(const char *name) {
    for (int i = 0; i < 5; i++)
        if (strcasecmp(name, LEVEL_NAME[i]) == 0) return (log_level_t)i;
    return LOG_INFO;
}

static int use_color(void) {
    return getenv("NO_COLOR") == NULL && isatty(fileno(stderr));
}

static void mkdir_p(const char *path) {
    char buf[512];
    snprintf(buf, sizeof buf, "%s", path);
    for (char *p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(buf, 0755);
            *p = '/';
        }
    }
    mkdir(buf, 0755);
}

static void open_log_file(void) {
    if (g_file) { fclose(g_file); g_file = NULL; }
    if (!g_cfg.enabled) return;

    mkdir_p(g_cfg.directory);
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", g_cfg.directory, g_cfg.file);
    g_file = fopen(path, "a");
    if (!g_file) {
        fprintf(stderr, "log: could not open %s for writing\n", path);
        g_file_size = 0;
        return;
    }
    g_file_size = ftell(g_file);
    if (g_file_size < 0) g_file_size = 0;
}

void log_init(const log_config_t *cfg, int verbose) {
    g_cfg = *cfg;
    g_min_level = (cfg->debug || verbose) ? LOG_DEBUG : cfg->level;
    g_use_color = use_color();
    open_log_file();
}

void log_set_hook(void (*hook)(log_level_t, const char *, const char *)) {
    g_hook = hook;
}

/* Rotate: file.(n-1) -> file.n (oldest dropped), then file -> file.1, same
 * shape as logging.handlers.RotatingFileHandler.doRollover. Best-effort --
 * a missing backup file at any step is normal (fewer rotations so far than
 * backup_count) and simply fails that rename, which we ignore. */
static void rotate_log(void) {
    if (g_file) { fclose(g_file); g_file = NULL; }
    char base[1024];
    snprintf(base, sizeof base, "%s/%s", g_cfg.directory, g_cfg.file);

    if (g_cfg.backup_count > 0) {
        char oldest[1152];
        snprintf(oldest, sizeof oldest, "%s.%d", base, g_cfg.backup_count);
        unlink(oldest);
        for (int i = g_cfg.backup_count - 1; i >= 1; i--) {
            char from[1152], to[1152];
            snprintf(from, sizeof from, "%s.%d", base, i);
            snprintf(to, sizeof to, "%s.%d", base, i + 1);
            rename(from, to);
        }
        char to1[1152];
        snprintf(to1, sizeof to1, "%s.1", base);
        rename(base, to1);
    } else {
        unlink(base);
    }
    open_log_file();
}

static void vformat(char *out, size_t outsz, const char *fmt, va_list ap) {
    vsnprintf(out, outsz, fmt, ap);
}

void log_write(log_level_t level, const char *tag, const char *fmt, ...) {
    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    vformat(msg, sizeof msg, fmt, ap);
    va_end(ap);

    if (level >= LOG_WARNING && g_hook) g_hook(level, tag, msg);

    if (level < g_min_level) return;

    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    char ts[32];
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tmv);

    if (g_use_color) {
        fprintf(stderr, "%s %s%-7s" RESET " %s: %s\n", ts, LEVEL_COLOR[level], LEVEL_NAME[level], tag, msg);
    } else {
        fprintf(stderr, "%s %-7s %s: %s\n", ts, LEVEL_NAME[level], tag, msg);
    }

    if (g_file) {
        int n = fprintf(g_file, "%s %-7s %s: %s\n", ts, LEVEL_NAME[level], tag, msg);
        fflush(g_file);
        if (n > 0) g_file_size += n;
        if (g_cfg.max_bytes > 0 && g_file_size >= g_cfg.max_bytes) rotate_log();
    }
}
