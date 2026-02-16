#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define INTERVAL 30
#define MEMORY_CORE "../memory/memory_core_cli"    // memory core executable
#define BASE_DIR "../memory/memory_store"          // scans stored inside memory/memory_store
#define SCANNERS_CONF "scanners.conf"
#define RETENTION_DAYS 7
#define MAX_SCANS 5000
#define MAX_LINE 1024
#define MAX_SCANNERS 64

typedef struct {
    char host[64];
    char type[64];
    char severity[8];
    char cmd[512];
} scanner_t;

int load_scanners(scanner_t *arr, int max) {
    FILE *f = fopen(SCANNERS_CONF, "r");
    if (!f) {
        fprintf(stderr, "Failed to open %s\n", SCANNERS_CONF);
        return 0;
    }

    char line[MAX_LINE];
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
        if (line[0]=='#' || line[0]=='\n') continue;
        line[strcspn(line, "\n")] = 0;

        char *host = strtok(line, "|");
        char *type = strtok(NULL, "|");
        char *sev  = strtok(NULL, "|");
        char *cmd  = strtok(NULL, "|");
        if (!host || !type || !sev || !cmd) continue;

        strncpy(arr[count].host, host, sizeof(arr[count].host)-1);
        strncpy(arr[count].type, type, sizeof(arr[count].type)-1);
        strncpy(arr[count].severity, sev, sizeof(arr[count].severity)-1);

        // prefix scanner command with relative path
        char scanner_path[512];
        snprintf(scanner_path, sizeof(scanner_path), "../scanner/%s", cmd);
        strncpy(arr[count].cmd, scanner_path, sizeof(arr[count].cmd)-1);

        count++;
        if (count >= max) break;
    }
    fclose(f);
    return count;
}

int main() {
    // ensure memory_store inside memory exists
    mkdir(BASE_DIR, 0755);

    scanner_t scanners[MAX_SCANNERS];
    int n = load_scanners(scanners, MAX_SCANNERS);
    if (n==0) {
        fprintf(stderr,"No scanners found in %s\n", SCANNERS_CONF);
        return 1;
    }

    while (1) {
        for (int i=0;i<n;i++) {
            pid_t pid = fork();
            if (pid==0) {
                // child process: scanner | memory_core_cli
                char mem_args[512];
                snprintf(mem_args, sizeof(mem_args),
                    "--host %s --type %s --severity %s --base-dir %s --retention-days %d --max-scans %d",
                    scanners[i].host, scanners[i].type, scanners[i].severity,
                    BASE_DIR, RETENTION_DAYS, MAX_SCANS);

                char full_cmd[1024];
                snprintf(full_cmd, sizeof(full_cmd), "%s | %s %s", scanners[i].cmd, MEMORY_CORE, mem_args);
                execlp("sh", "sh", "-c", full_cmd, NULL);

                perror("execlp failed");
                exit(1);
            }
        }

        // wait for all child processes
        while(wait(NULL) > 0);

        sleep(INTERVAL);
    }

    return 0;
}
