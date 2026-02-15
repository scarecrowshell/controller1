// controller.c
#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>

typedef struct {
    GtkTextBuffer *buffer;
    GtkTextView *view;
    pid_t pid;
    int fd;
    gboolean separate_lines;
} process_t;

static void append_text(process_t *proc, const char *text) {
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(proc->buffer, &end);

    char tmp[8192];
    strncpy(tmp, text, sizeof(tmp)-1);
    tmp[sizeof(tmp)-1] = 0;

    if (!proc->separate_lines) {
        gtk_text_buffer_insert(proc->buffer, &end, tmp, -1);
    } else {
        for (char *p = tmp; *p; p++) if (*p=='\n') *p=',';
        gtk_text_buffer_insert(proc->buffer, &end, tmp, -1);
        gtk_text_buffer_insert(proc->buffer, &end, "\n", -1);
    }

    GtkAdjustment *vadj = gtk_scrollable_get_vadjustment(GTK_SCROLLABLE(proc->view));
    gtk_adjustment_set_value(vadj, gtk_adjustment_get_upper(vadj));
}

static gboolean check_process(gpointer data) {
    process_t *proc = (process_t *)data;
    if (proc->fd < 0) return G_SOURCE_REMOVE;

    char buf[512];
    ssize_t n = read(proc->fd, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = 0;
        append_text(proc, buf);
    }

    int status;
    pid_t result = waitpid(proc->pid, &status, WNOHANG);
    if (result == proc->pid) {
        append_text(proc, "[PROCESS EXITED]\n");
        close(proc->fd);
        proc->fd = -1;
        return G_SOURCE_REMOVE;
    }

    return TRUE;
}

static void start_process(const char *path, process_t *proc, gboolean separate_lines) {
    int pipefd[2];
    if (pipe(pipefd) < 0) return;

    pid_t pid = fork();
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execl(path, path, NULL);
        perror("execl failed");
        exit(1);
    } else if (pid > 0) {
        close(pipefd[1]);
        proc->pid = pid;
        proc->fd = pipefd[0];
        proc->separate_lines = separate_lines;
        fcntl(proc->fd, F_SETFL, O_NONBLOCK);
        g_timeout_add(100, check_process, proc);
    }
}

int main(int argc, char **argv) {
    gtk_init(&argc, &argv);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Controller");
    gtk_window_set_default_size(GTK_WINDOW(window), 1800, 1000);
    gtk_window_set_resizable(GTK_WINDOW(window), TRUE);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *scroll_outer = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll_outer),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(window), scroll_outer);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_add(GTK_CONTAINER(scroll_outer), grid);

    const char *rows[] = {
        "scheduler core",
        "scanner core",
        "telemetry core", "healing core", "vulnerabilityscanning core",
        "internalanalysis core", "interface core", "higherfunctionality core", "personality core",
        "memory core", "venom core", "iron core", "garden core", "silk core"
    };

    int total_rows = sizeof(rows)/sizeof(rows[0]);
    process_t processes[15];

    for (int i = 0; i < total_rows; i++) {
        GtkWidget *label = gtk_label_new(rows[i]);
        gtk_label_set_xalign(GTK_LABEL(label), 0.0);
        gtk_widget_set_hexpand(label, TRUE);
        gtk_widget_set_halign(label, GTK_ALIGN_START);
        gtk_grid_attach(GTK_GRID(grid), label, 0, i, 1, 1);

        GtkWidget *scrolled = gtk_scrolled_window_new(NULL, NULL);
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                                       GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
        gtk_widget_set_size_request(scrolled, 1200, 150);
        gtk_grid_attach(GTK_GRID(grid), scrolled, 1, i, 1, 1);

        GtkWidget *view = gtk_text_view_new();
        gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
        gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_NONE);
        gtk_container_add(GTK_CONTAINER(scrolled), view);

        GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));

        processes[i].buffer = buf;
        processes[i].view = GTK_TEXT_VIEW(view);
        processes[i].fd = -1;

        if (i == 0) { // Scheduler Core
            start_process("/home/kali/Desktop/heartbeat/scheduler/scheduler", &processes[i], FALSE);
        } else if (i == 1) { // Scanner Core
            start_process("/home/kali/Desktop/scanner/scanner/pid_probe", &processes[i], TRUE);
        }
    }

    gtk_widget_show_all(window);
    gtk_main();

    return 0;
}
