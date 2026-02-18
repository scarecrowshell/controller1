// controller.c
// Robust controller (updated): replaces usleep() with nanosleep() and adds missing headers.
// Place at: scarecrow/controller/controller.c

#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <dirent.h>
#include <limits.h>
#include <ctype.h>
#include <time.h>

#define INTERVAL 30
#define MEMORY_CORE "../memory/memory_core_cli"
#define BASE_DIR "../memory/memory_store"
#define SCANNERS_CONF "scanners.conf"
#define RETENTION_MINUTES 10
#define CLEAN_INTERVAL_SECONDS (RETENTION_MINUTES * 60)
#define MAX_LINE 1024
#define MAX_SCANNERS 128

typedef struct {
    char host[128];
    char type[128];
    char severity[16];
    char cmd[1024];
    pid_t pid;     /* child PID (session leader) */
} scanner_t;

static volatile sig_atomic_t stop_requested = 0;
static volatile sig_atomic_t cleanup_requested = 0; /* set by SIGTSTP handler */
static scanner_t scanners[MAX_SCANNERS];
static int scanner_count = 0;

/* forward */
static void kill_all_scanners(void);
static void robust_scan_and_kill_stragglers(void);

/* signal handlers (async-signal-safe actions only) */
static void handle_term(int sig) { (void)sig; stop_requested = 1; }
static void handle_tstp(int sig) {
    (void)sig;
    /* request cleanup in main loop (do NOT perform heavy ops here) */
    cleanup_requested = 1;
}

/* Load scanners.conf */
static int load_scanners(void) {
    FILE *f = fopen(SCANNERS_CONF, "r");
    if (!f) {
        fprintf(stderr, "Failed to open %s: %s\n", SCANNERS_CONF, strerror(errno));
        return 0;
    }
    char line[MAX_LINE];
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '#' || *s == '\n' || *s == '\0') continue;
        line[strcspn(line, "\n")] = 0;
        char *host = strtok(line, "|");
        char *type = strtok(NULL, "|");
        char *sev  = strtok(NULL, "|");
        char *cmd  = strtok(NULL, "|");
        if (!host || !type || !sev || !cmd) continue;
        strncpy(scanners[count].host, host, sizeof(scanners[count].host)-1);
        scanners[count].host[sizeof(scanners[count].host)-1] = '\0';
        strncpy(scanners[count].type, type, sizeof(scanners[count].type)-1);
        scanners[count].type[sizeof(scanners[count].type)-1] = '\0';
        strncpy(scanners[count].severity, sev, sizeof(scanners[count].severity)-1);
        scanners[count].severity[sizeof(scanners[count].severity)-1] = '\0';
        snprintf(scanners[count].cmd, sizeof(scanners[count].cmd), "../scanner/%s", cmd);
        scanners[count].cmd[sizeof(scanners[count].cmd)-1] = '\0';
        scanners[count].pid = 0;
        count++;
        if (count >= MAX_SCANNERS) break;
    }
    fclose(f);
    scanner_count = count;
    return count;
}

/* Normal shutdown: SIGTERM then SIGKILL to process groups */
static void kill_all_scanners(void) {
    for (int i = 0; i < scanner_count; ++i) {
        pid_t p = scanners[i].pid;
        if (p > 0) kill(-p, SIGTERM);
    }
    sleep(1);
    for (int i = 0; i < scanner_count; ++i) {
        pid_t p = scanners[i].pid;
        if (p > 0) kill(-p, SIGKILL);
    }
}

/* Robust scan of /proc to find stray scanner or memory_core_cli processes and kill them.
   This runs in main context (not in signal handler) so it can do I/O. */
static void robust_scan_and_kill_stragglers(void) {
    DIR *d = opendir("/proc");
    if (!d) return;
    struct dirent *e;
    char exe_path[PATH_MAX];
    struct timespec ts = {0, 100000000}; /* 100ms */

    while ((e = readdir(d)) != NULL) {
        if (!isdigit((unsigned char)e->d_name[0])) continue;
        pid_t pid = (pid_t)atoi(e->d_name);
        if (pid <= 1) continue;

        /* skip if this pid is one of the known session leaders we already killed */
        int known = 0;
        for (int i = 0; i < scanner_count; ++i) {
            if (scanners[i].pid == pid) { known = 1; break; }
            if (scanners[i].pid > 0) {
                pid_t pg = getpgid(pid);
                pid_t spg = getpgid(scanners[i].pid);
                if (pg != -1 && spg != -1 && pg == spg) { known = 1; break; }
            }
        }
        if (known) continue;

        /* read /proc/<pid>/exe */
        char link[PATH_MAX];
        snprintf(link, sizeof(link), "/proc/%d/exe", pid);
        ssize_t r = readlink(link, exe_path, sizeof(exe_path)-1);
        if (r <= 0) continue;
        exe_path[r] = '\0';

        /* if executable path contains scanner dir or memory_core_cli, kill it */
        if (strstr(exe_path, "/scarecrow/scanner/") != NULL ||
            strstr(exe_path, "/scarecrow/memory/memory_core_cli") != NULL ||
            strstr(exe_path, "memory_core_cli") != NULL) {
            kill(pid, SIGTERM);
            nanosleep(&ts, NULL);
            if (kill(pid, 0) == 0) kill(pid, SIGKILL);
            continue;
        }

        /* also check cmdline for references */
        char cmdline_path[PATH_MAX];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
        FILE *cf = fopen(cmdline_path, "r");
        if (cf) {
            char buf[4096];
            size_t len = fread(buf, 1, sizeof(buf)-1, cf);
            fclose(cf);
            buf[len] = '\0';
            if (strstr(buf, "scanner_") || strstr(buf, "memory_core_cli") || strstr(buf, "scarecrow/scanner")) {
                kill(pid, SIGTERM);
                nanosleep(&ts, NULL);
                if (kill(pid, 0) == 0) kill(pid, SIGKILL);
            }
        }
    }
    closedir(d);
}

/* Optional: periodic cleanup thread that wipes BASE_DIR every CLEAN_INTERVAL_SECONDS */
static void *cleanup_thread_fn(void *arg) {
    const char *base = (const char *)arg;
    for (;;) {
        sleep(CLEAN_INTERVAL_SECONDS);
        char cmd[PATH_MAX + 256];
        snprintf(cmd, sizeof(cmd),
                 "sh -c 'rm -rf \"%s\"/* \"%s\"/.[!.]* \"%s\"/..?*' 2>/dev/null || true",
                 base, base, base);
        system(cmd);
        if (access(base, F_OK) != 0) mkdir(base, 0755);
        fprintf(stdout, "[CLEANUP] wiped %s\n", base);
        fflush(stdout);
    }
    return NULL;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_term;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct sigaction st;
    memset(&st, 0, sizeof(st));
    st.sa_handler = handle_tstp;
    sigaction(SIGTSTP, &st, NULL);

    if (mkdir(BASE_DIR, 0755) != 0 && errno != EEXIST) {
        /* continue */
    }

    if (load_scanners() == 0) {
        fprintf(stderr, "No scanners found in %s\n", SCANNERS_CONF);
        return 1;
    }

    /* start cleanup thread (optional) */
    pthread_t cleaner;
    if (pthread_create(&cleaner, NULL, cleanup_thread_fn, (void *)BASE_DIR) == 0) {
        pthread_detach(cleaner);
    }

    while (!stop_requested) {
        /* spawn each scanner as a child session leader so pipeline can be killed by killing -pid */
        for (int i = 0; i < scanner_count && !stop_requested; ++i) {
            pid_t pid = fork();
            if (pid < 0) {
                fprintf(stderr, "fork failed for %s\n", scanners[i].cmd);
                scanners[i].pid = 0;
                continue;
            }
            if (pid == 0) {
                /* child: create new session */
                setsid(); /* ignore errors */
                char mem_args[1024];
                snprintf(mem_args, sizeof(mem_args),
                         "--host %s --type %s --severity %s --base-dir %s --retention-minutes %d",
                         scanners[i].host, scanners[i].type, scanners[i].severity,
                         BASE_DIR, RETENTION_MINUTES);
                char full_cmd[2048];
                snprintf(full_cmd, sizeof(full_cmd), "%s | %s %s", scanners[i].cmd, MEMORY_CORE, mem_args);
                execlp("sh", "sh", "-c", full_cmd, (char *)NULL);
                _exit(127);
            }
            /* parent records child pid (session leader) */
            scanners[i].pid = pid;
        }

        /* If a suspend was requested (SIGTSTP), perform robust cleanup BEFORE actually suspending */
        if (cleanup_requested) {
            /* normal graceful kills for known groups */
            kill_all_scanners();
            /* then scan /proc for any stray scanner/memory_core processes and kill them */
            robust_scan_and_kill_stragglers();
            /* reset flag and actually suspend controller process now */
            cleanup_requested = 0;
            raise(SIGSTOP); /* actually suspend after cleanup */
        }

        /* wait for children (non-blocking) until they finish or stop requested */
        int remaining = 0;
        for (int i = 0; i < scanner_count; ++i) if (scanners[i].pid > 0) remaining++;
        while (remaining > 0 && !stop_requested) {
            pid_t w = waitpid(-1, NULL, WNOHANG);
            if (w > 0) {
                for (int i = 0; i < scanner_count; ++i) {
                    if (scanners[i].pid == w) {
                        scanners[i].pid = 0;
                        remaining--;
                        break;
                    }
                }
            } else {
                sleep(1);
            }
        }

        if (stop_requested) break;

        for (int s = 0; s < INTERVAL && !stop_requested; ++s) sleep(1);
    }

    /* on shutdown: ensure all scanner groups are terminated */
    kill_all_scanners();

    /* final sweep for stray processes */
    robust_scan_and_kill_stragglers();

    /* reap any remaining children */
    while (waitpid(-1, NULL, WNOHANG) > 0) {}

    return 0;
}
