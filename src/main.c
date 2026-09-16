/* Entrypoint. Ported (reduced scope for v1.0.1 -- see the plan) from
 * sekurircd/src/sekurircd/app.py: argument parsing, --hash-password,
 * config/logging setup, POSIX double-fork --daemon, --pidfile, and
 * --stop/--rehash (signal the pidfile's PID and, for --stop, wait for exit),
 * and /RESTART's in-place execv re-exec.
 */
#include "config.h"
#include "crypto.h"
#include "log.h"
#include "net.h"
#include "server.h"
#include "version.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static void usage(const char *prog) {
    printf("usage: %s [-c|--config PATH] [-v|--verbose] [--hash-password] [--version]\n"
           "       %*s [-d|--daemon] [--pidfile PATH] [--stop] [--rehash]\n",
           prog, (int)strlen(prog), "");
}

static void read_password_noecho(const char *prompt, char *out, size_t outsz) {
    printf("%s", prompt);
    fflush(stdout);
    struct termios oldt, newt;
    int have_tty = isatty(STDIN_FILENO);
    if (have_tty) {
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }
    if (!fgets(out, (int)outsz, stdin)) out[0] = '\0';
    if (have_tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        printf("\n");
    }
    size_t len = strlen(out);
    while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r')) out[--len] = '\0';
}

static int hash_password_cli(void) {
    char pw1[256], pw2[256];
    read_password_noecho("Password: ", pw1, sizeof pw1);
    read_password_noecho("Confirm password: ", pw2, sizeof pw2);
    if (strcmp(pw1, pw2) != 0) { fprintf(stderr, "Passwords do not match.\n"); return 1; }
    if (pw1[0] == '\0') { fprintf(stderr, "Password must not be empty.\n"); return 1; }
    char hash[256];
    if (crypto_hash_password(pw1, hash, sizeof hash) != 0) { fprintf(stderr, "Hashing failed.\n"); return 1; }
    printf("%s\n", hash);
    return 0;
}

/* POSIX classic double-fork daemonize -- detach from the controlling
 * terminal. Deliberately does NOT chdir("/"): [logging].directory and the
 * MOTD/klines paths resolve against the CWD/config-file-dir at startup (see
 * config.h), and chdir-ing first would silently break that with stdio
 * already redirected to /dev/null. */
static void daemonize(void) {
    if (fork() > 0) _exit(0);
    setsid();
    if (fork() > 0) _exit(0);
    umask(0022);
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, 0);
        dup2(devnull, 1);
        dup2(devnull, 2);
        if (devnull > 2) close(devnull);
    }
}

static long read_pidfile(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    long pid;
    int ok = fscanf(fp, "%ld", &pid) == 1;
    fclose(fp);
    return ok ? pid : -1;
}

static int pidfile_is_live(const char *path) {
    long pid = read_pidfile(path);
    if (pid <= 0) return 0;
    /* A /RESTART re-exec keeps the same PID and deliberately leaves the
     * pidfile in place (see main()'s restart handling below) -- on the
     * re-exec'd process's own startup, that pidfile names *this* process,
     * which is trivially "live" but is not a second instance to refuse. */
    if ((pid_t)pid == getpid()) return 0;
    return kill((pid_t)pid, 0) == 0;
}

static int stop_daemon(const char *pidfile, double timeout) {
    long pid = read_pidfile(pidfile);
    if (pid <= 0) {
        fprintf(stderr, "sekurircd: no running daemon (can't read a pid from %s)\n", pidfile);
        return 1;
    }
    if (kill((pid_t)pid, SIGTERM) != 0) {
        if (errno == ESRCH) {
            fprintf(stderr, "sekurircd: process %ld is not running (stale pidfile %s)\n", pid, pidfile);
            unlink(pidfile);
        } else {
            fprintf(stderr, "sekurircd: could not signal process %ld: %s\n", pid, strerror(errno));
        }
        return 1;
    }
    time_t deadline = time(NULL) + (time_t)timeout;
    while (time(NULL) < deadline) {
        if (kill((pid_t)pid, 0) != 0 && errno == ESRCH) {
            printf("sekurircd: stopped (pid %ld)\n", pid);
            return 0;
        }
        struct timespec ts = {0, 200000000L};
        nanosleep(&ts, NULL);
    }
    fprintf(stderr, "sekurircd: process %ld did not stop within %.0fs\n", pid, timeout);
    return 1;
}

static int rehash_daemon(const char *pidfile) {
    long pid = read_pidfile(pidfile);
    if (pid <= 0) {
        fprintf(stderr, "sekurircd: no running daemon (can't read a pid from %s)\n", pidfile);
        return 1;
    }
    if (kill((pid_t)pid, SIGHUP) != 0) {
        if (errno == ESRCH) fprintf(stderr, "sekurircd: process %ld is not running (stale pidfile %s)\n", pid, pidfile);
        else fprintf(stderr, "sekurircd: could not signal process %ld: %s\n", pid, strerror(errno));
        return 1;
    }
    printf("sekurircd: rehash requested (pid %ld) -- check its log for the result\n", pid);
    return 0;
}

int main(int argc, char **argv) {
    const char *config_path = getenv("SEKURIRCD_CONFIG");
    const char *pidfile = getenv("SEKURIRCD_PIDFILE");
    if (!pidfile) pidfile = "sekurircd.pid";
    int verbose = 0, do_hash = 0, do_daemon = 0, do_stop = 0, do_rehash = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if ((strcmp(a, "-c") == 0 || strcmp(a, "--config") == 0) && i + 1 < argc) config_path = argv[++i];
        else if (strcmp(a, "-v") == 0 || strcmp(a, "--verbose") == 0) verbose = 1;
        else if (strcmp(a, "--hash-password") == 0) do_hash = 1;
        else if (strcmp(a, "-d") == 0 || strcmp(a, "--daemon") == 0) do_daemon = 1;
        else if (strcmp(a, "--pidfile") == 0 && i + 1 < argc) pidfile = argv[++i];
        else if (strcmp(a, "--stop") == 0) do_stop = 1;
        else if (strcmp(a, "--rehash") == 0) do_rehash = 1;
        else if (strcmp(a, "--version") == 0) { printf("sekurircd %s\n", SEKURIRCD_VERSION); return 0; }
        else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unrecognized argument: %s\n", a); usage(argv[0]); return 2; }
    }

    if (do_hash) return hash_password_cli();
    if (do_stop) return stop_daemon(pidfile, 10.0);
    if (do_rehash) return rehash_daemon(pidfile);

    config_t cfg;
    char errbuf[512];
    if (config_load(config_path, &cfg, errbuf, sizeof errbuf) != 0) {
        fprintf(stderr, "sekurircd: configuration error: %s\n", errbuf);
        return 2;
    }

    if (pidfile[0] && pidfile_is_live(pidfile)) {
        long existing = read_pidfile(pidfile);
        fprintf(stderr, "sekurircd: a daemon is already running (pid %ld, pidfile %s) "
                         "-- refusing to start a second one and clobber its pidfile\n",
                existing, pidfile);
        return 2;
    }

    if (do_daemon) daemonize();

    if (pidfile[0]) {
        FILE *fp = fopen(pidfile, "w");
        if (fp) { fprintf(fp, "%d\n", (int)getpid()); fclose(fp); }
    }

    log_config_t lcfg = {
        .enabled = cfg.logging.enabled,
        .debug = cfg.logging.debug,
        .level = log_level_from_name(cfg.logging.level),
        .max_bytes = cfg.logging.max_bytes,
        .backup_count = cfg.logging.backup_count,
    };
    snprintf(lcfg.directory, sizeof lcfg.directory, "%s", cfg.logging.directory);
    snprintf(lcfg.file, sizeof lcfg.file, "%s", cfg.logging.file);
    log_init(&lcfg, verbose);

    log_info("main", "sekurircd %s starting (config: %s)", SEKURIRCD_VERSION,
              cfg.path[0] ? cfg.path : "<built-in defaults>");
    if (cfg.github_monitor_enabled)
        log_warn("main", "[github_monitor] is enabled in config but not implemented in this C port -- ignoring");

    server_t srv;
    server_init(&srv, &cfg);

    int rc = net_run(&srv);
    int restart = srv.restart_requested;

    /* A /RESTART re-execs this same PID in place, so the pidfile stays
     * valid and correct -- only remove it on a real exit. */
    if (pidfile[0] && !restart) unlink(pidfile);

    if (restart) {
        log_info("main", "restarting: re-executing %s", argv[0]);
        execv(argv[0], argv);
        log_error("main", "execv failed: %s -- exiting instead", strerror(errno));
        return 1;
    }
    return rc == 0 ? 0 : 1;
}
