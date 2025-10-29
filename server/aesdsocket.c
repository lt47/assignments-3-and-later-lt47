#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <sys/queue.h>

#include "aesd_ioctl.h"

#define PORT "9000"

#ifndef USE_AESD_CHAR_DEVICE
#define USE_AESD_CHAR_DEVICE 1
#endif

#if USE_AESD_CHAR_DEVICE
#define DATAFILE "/dev/aesdchar"
#else
#define DATAFILE "/var/tmp/aesdsocketdata"
#endif

#define BUF_SIZE 1024

static int server_fd = -1;
static volatile sig_atomic_t stop = 0;
pthread_mutex_t file_lock = PTHREAD_MUTEX_INITIALIZER;

struct client_thread {
    pthread_t tid;
    int cfd;
    _Atomic bool done;
    SLIST_ENTRY(client_thread) entries;
};
SLIST_HEAD(thread_list, client_thread) head = SLIST_HEAD_INITIALIZER(head);

#define LOGI(fmt, ...) syslog(LOG_INFO, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) syslog(LOG_ERR,  fmt, ##__VA_ARGS__)

static void signal_handler(int sig)
{
    stop = 1;
    if (server_fd != -1) {
        close(server_fd);
        server_fd = -1;
    }
    syslog(LOG_INFO, "Caught signal %d, shutting down", sig);
}

static ssize_t write_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    while (len > 0) {
        ssize_t w = write(fd, p, len);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += (size_t)w;
        len -= (size_t)w;
    }
    return 0;
}

static int send_from_fd(int cfd, int datafd)
{
    char buf[BUF_SIZE];
    for (;;) {
        ssize_t n = read(datafd, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) break;
        if (write_all(cfd, buf, (size_t)n) < 0) return -1;
    }
    return 0;
}

#if !USE_AESD_CHAR_DEVICE
static int compute_seek_offset_from_file(int fd, unsigned cmd_index, unsigned cmd_offset, off_t *target_pos)
{
    off_t pos = 0;
    unsigned cur_cmd = 0;
    off_t cmd_start = 0;
    off_t cmd_end = -1;
    char buf[BUF_SIZE];
    ssize_t n;

    if (cmd_index == 0) cmd_start = 0;
    else cmd_start = -1;

    if (lseek(fd, 0, SEEK_SET) < 0) return -1;

    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; ++i) {
            char ch = buf[i];
            if (cur_cmd == cmd_index && cmd_start == -1) {
            }
            if (ch == '\n') {
                if (cur_cmd == cmd_index) {
                    cmd_end = pos + i + 1;
                    goto found;
                }
                cur_cmd++;
                if (cur_cmd == cmd_index) {
                    cmd_start = pos + i + 1;
                }
            }
        }
        pos += n;
    }

    if (cmd_start != -1 && cmd_end == -1) {
        if (cur_cmd == cmd_index) {
            cmd_end = pos;
            goto found;
        }
    }

    return -1;

found:
    if (cmd_start == -1) {
        cmd_start = 0;
    }
    off_t entry_size = cmd_end - cmd_start;
    if ((off_t)cmd_offset > entry_size) return -1;

    *target_pos = cmd_start + (off_t)cmd_offset;
    return 0;
}
#endif

static int parse_seekto_line(const char *line, size_t len, struct aesd_seekto *seekto)
{
    static const char prefix[] = "AESDCHAR_IOCSEEKTO:";
    size_t plen = sizeof(prefix) - 1;

    if (len < plen + 3) return 0;
    if (strncmp(line, prefix, plen) != 0) return 0;

    char tmp[256];
    size_t cpy = len < sizeof(tmp) - 1 ? len : sizeof(tmp) - 1;
    memcpy(tmp, line, cpy);
    tmp[cpy] = '\0';

    unsigned cmd = 0, off = 0;
    if (sscanf(tmp + plen, "%u,%u", &cmd, &off) == 2) {
        seekto->write_cmd = cmd;
        seekto->write_cmd_offset = off;
        return 1;
    }
    return -1;
}

static void *client_handler(void *arg)
{
    struct client_thread *node = arg;
    int cfd = node->cfd;
    char *acc = NULL;
    size_t acc_len = 0, acc_cap = 0;

    for (;;) {
        char buf[BUF_SIZE];
        ssize_t n = recv(cfd, buf, sizeof buf, 0);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            LOGE("recv failed: %s", strerror(errno));
            break;
        }

        if (acc_len + (size_t)n > acc_cap) {
            size_t newcap = acc_cap ? acc_cap : 2048;
            while (acc_len + (size_t)n > newcap) newcap *= 2;
            char *tmp = realloc(acc, newcap);
            if (!tmp) { LOGE("realloc failed"); break; }
            acc = tmp; acc_cap = newcap;
        }
        memcpy(acc + acc_len, buf, (size_t)n);
        acc_len += (size_t)n;

        size_t scan = 0;
        while (scan < acc_len) {
            char *nl = memchr(acc + scan, '\n', acc_len - scan);
            if (!nl) break;
            size_t line_end = (size_t)(nl - acc) + 1;
            size_t line_len = line_end - scan;

#if USE_AESD_CHAR_DEVICE
            pthread_mutex_lock(&file_lock);
            int datafd = open(DATAFILE, O_RDWR);
            if (datafd < 0) {
                pthread_mutex_unlock(&file_lock);
                LOGE("open(%s): %s", DATAFILE, strerror(errno));
                goto next;
            }

            struct aesd_seekto seekto;
            int parsed = parse_seekto_line(acc + scan, line_len, &seekto);
            if (parsed == 1) {
                if (ioctl(datafd, AESDCHAR_IOCSEEKTO, &seekto) != 0)
                    LOGE("ioctl failed: %s", strerror(errno));
                send_from_fd(cfd, datafd);
            } else if (parsed == 0) {
                write_all(datafd, acc + scan, line_len);
                lseek(datafd, 0, SEEK_SET);
                send_from_fd(cfd, datafd);
            } else {
                LOGE("Malformed AESDCHAR_IOCSEEKTO");
            }
            close(datafd);
            pthread_mutex_unlock(&file_lock);
#else
            pthread_mutex_lock(&file_lock);

            struct aesd_seekto seekto;
            int parsed = parse_seekto_line(acc + scan, line_len, &seekto);
            if (parsed == 1) {
                int fd = open(DATAFILE, O_RDONLY);
                if (fd < 0) {
                    LOGE("open(%s): %s", DATAFILE, strerror(errno));
                } else {
                    off_t target = 0;
                    if (compute_seek_offset_from_file(fd, seekto.write_cmd, seekto.write_cmd_offset, &target) == 0) {
                        if (lseek(fd, target, SEEK_SET) < 0) {
                            LOGE("lseek failed: %s", strerror(errno));
                        } else {
                            send_from_fd(cfd, fd);
                        }
                    } else {
                        LOGE("Malformed AESDCHAR_IOCSEEKTO or invalid args");
                    }
                    close(fd);
                }
            } else if (parsed == 0) {
                int fd = open(DATAFILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
                if (fd >= 0) {
                    write_all(fd, acc + scan, line_len);
                    fsync(fd);
                    close(fd);
                } else {
                    LOGE("open(%s) for append failed: %s", DATAFILE, strerror(errno));
                }
                fd = open(DATAFILE, O_RDONLY);
                if (fd >= 0) {
                    send_from_fd(cfd, fd);
                    close(fd);
                } else {
                    LOGE("open(%s) for read failed: %s", DATAFILE, strerror(errno));
                }
            } else {
                LOGE("Malformed AESDCHAR_IOCSEEKTO");
            }

            pthread_mutex_unlock(&file_lock);
#endif
        next:
            scan = line_end;
        }
        if (scan > 0) {
            size_t rem = acc_len - scan;
            memmove(acc, acc + scan, rem);
            acc_len = rem;
        }
    }

    free(acc);
    close(cfd);
    node->done = true;
    return NULL;
}

static void daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    if (setsid() < 0) exit(EXIT_FAILURE);
    if (chdir("/") != 0) exit(EXIT_FAILURE);

    close(STDIN_FILENO); close(STDOUT_FILENO); close(STDERR_FILENO);
    int dn = open("/dev/null", O_RDWR);
    if (dn >= 0) {
        dup2(dn, STDIN_FILENO);
        dup2(dn, STDOUT_FILENO);
        dup2(dn, STDERR_FILENO);
        if (dn > 2) close(dn);
    }
}

int main(int argc, char *argv[])
{
    bool daemon = (argc == 2 && strcmp(argv[1], "-d") == 0);
    openlog("aesdsocket", LOG_PID, LOG_USER);
    LOGI("aesdsocket starting...");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

#if !USE_AESD_CHAR_DEVICE
    int fd = open(DATAFILE, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd >= 0) close(fd);
#endif
    if (daemon) daemonize();

    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(NULL, PORT, &hints, &res) != 0) return EXIT_FAILURE;

    server_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    int yes = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    if (bind(server_fd, res->ai_addr, res->ai_addrlen) < 0) return EXIT_FAILURE;
    freeaddrinfo(res);
    if (listen(server_fd, 10) < 0) return EXIT_FAILURE;
    LOGI("Listening on port %s", PORT);

#if !USE_AESD_CHAR_DEVICE
    pthread_t ts_tid;
    pthread_create(&ts_tid, NULL, timestamp_thread, NULL);
#endif

    SLIST_INIT(&head);
    while (!stop) {
        int cfd = accept(server_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR && stop) break;
            continue;
        }
        struct client_thread *node = calloc(1, sizeof *node);
        node->cfd = cfd; node->done = false;
        pthread_create(&node->tid, NULL, client_handler, node);
        SLIST_INSERT_HEAD(&head, node, entries);

        struct client_thread *cur = SLIST_FIRST(&head);
        while (cur) {
            struct client_thread *next = SLIST_NEXT(cur, entries);
            if (cur->done) {
                pthread_join(cur->tid, NULL);
                SLIST_REMOVE(&head, cur, client_thread, entries);
                free(cur);
            }
            cur = next;
        }
    }

    while (!SLIST_EMPTY(&head)) {
        struct client_thread *n = SLIST_FIRST(&head);
        SLIST_REMOVE_HEAD(&head, entries);
        pthread_join(n->tid, NULL);
        free(n);
    }

#if !USE_AESD_CHAR_DEVICE
    pthread_join(ts_tid, NULL);
    unlink(DATAFILE);
#endif

    LOGI("aesdsocket exiting");
    closelog();
    return 0;
}
