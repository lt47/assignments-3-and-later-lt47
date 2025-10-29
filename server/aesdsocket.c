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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <sys/queue.h>

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
#define LOGE(fmt, ...) syslog(LOG_ERR, fmt, ##__VA_ARGS__)


void signal_handler(int sig)
{
    stop = 1;
    if (server_fd != -1) {
        close(server_fd);
        server_fd = -1;
    }
    syslog(LOG_INFO, "Caught signal %d, shutting down", sig);
}


ssize_t write_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    while (len > 0) {
        ssize_t w = write(fd, p, len);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += w;
        len -= w;
    }
    return 0;
}


void append_to_file(const void *buf, size_t len)
{
    pthread_mutex_lock(&file_lock);
    int fd = open(DATAFILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        write_all(fd, buf, len);
        fsync(fd);
        close(fd);
    }
    pthread_mutex_unlock(&file_lock);
}

void send_file(int cfd)
{
    pthread_mutex_lock(&file_lock);
    int fd = open(DATAFILE, O_RDONLY);
    if (fd >= 0) {
        char buf[BUF_SIZE];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0)
            write_all(cfd, buf, (size_t)n);
        close(fd);
    }
    pthread_mutex_unlock(&file_lock);
}


#if !USE_AESD_CHAR_DEVICE
void *timestamp_thread(void *arg)
{
    (void)arg;
    while (!stop) {
        sleep(10);
        if (stop) break;

        time_t now = time(NULL);
        char tbuf[128];
        struct tm *tm_info = localtime(&now);
        strftime(tbuf, sizeof(tbuf), "timestamp: %a, %d %b %Y %T %z\n", tm_info);
        append_to_file(tbuf, strlen(tbuf));
    }
    return NULL;
}
#endif


void *client_handler(void *arg)
{
    struct client_thread *node = (struct client_thread *)arg;
    int cfd = node->cfd;

    char buf[BUF_SIZE];
    ssize_t n;
    while ((n = recv(cfd, buf, sizeof(buf), 0)) > 0) {
        append_to_file(buf, n);
        if (memchr(buf, '\n', n))
            send_file(cfd);
    }

    close(cfd);
    node->done = true;
    return NULL;
}


void daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    if (setsid() < 0) exit(EXIT_FAILURE);
    if (chdir("/") != 0) exit(EXIT_FAILURE);

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > 2) close(devnull);
    }
}


int main(int argc, char *argv[])
{
    bool daemon = (argc == 2 && strcmp(argv[1], "-d") == 0);

    openlog("aesdsocket", LOG_PID, LOG_USER);
    syslog(LOG_INFO, "aesdsocket starting...");

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

    if (getaddrinfo(NULL, PORT, &hints, &res) != 0) {
        syslog(LOG_ERR, "getaddrinfo failed");
        return EXIT_FAILURE;
    }

    server_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (server_fd < 0) {
        syslog(LOG_ERR, "socket failed");
        return EXIT_FAILURE;
    }

    int yes = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    if (bind(server_fd, res->ai_addr, res->ai_addrlen) < 0) {
        syslog(LOG_ERR, "bind failed: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    freeaddrinfo(res);

    if (listen(server_fd, 10) < 0) {
        syslog(LOG_ERR, "listen failed");
        return EXIT_FAILURE;
    }
    syslog(LOG_INFO, "Listening on port %s", PORT);

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

        struct client_thread *node = calloc(1, sizeof(*node));
        node->cfd = cfd;
        node->done = false;

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

    syslog(LOG_INFO, "aesdsocket exiting");
    closelog();
    return 0;
}
