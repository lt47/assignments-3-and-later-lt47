#include <arpa/inet.h>
#include <errno.h>
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
#include <fcntl.h>

#define PORT "9000"
#define BACKLOG 10
#define DATAFILE "/var/tmp/aesdsocketdata"
#define BUFSIZE 1024

static volatile sig_atomic_t exit_flag = 0;
static int listen_fd = -1;

pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct thread_node {
    pthread_t thread_id;
    int client_fd;
    struct thread_node *next;
} thread_node_t;

static thread_node_t *thread_list_head = NULL;
pthread_mutex_t thread_list_mutex = PTHREAD_MUTEX_INITIALIZER;

void handle_signal(int signo) {
    syslog(LOG_INFO, "Caught signal, exiting");
    exit_flag = 1;
    if (listen_fd != -1) close(listen_fd);
}

void *timestamp_thread(void *arg) {
    (void)arg;
    while (!exit_flag) {
        sleep(10);
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char time_str[128];
        strftime(time_str, sizeof(time_str), "timestamp:%a, %d %b %Y %H:%M:%S %z\n", t);

        pthread_mutex_lock(&file_mutex);
        int fd = open(DATAFILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd != -1) {
            write(fd, time_str, strlen(time_str));
            close(fd);
        } else {
            syslog(LOG_ERR, "timestamp write failed: %s", strerror(errno));
        }
        pthread_mutex_unlock(&file_mutex);
    }
    return NULL;
}

int send_file(int client_fd) {
    pthread_mutex_lock(&file_mutex);
    int fd = open(DATAFILE, O_RDONLY);
    if (fd == -1) {
        pthread_mutex_unlock(&file_mutex);
        return 0;
    }
    char buf[BUFSIZE];
    ssize_t r;
    while ((r = read(fd, buf, sizeof(buf))) > 0) {
        ssize_t sent = 0;
        while (sent < r) {
            ssize_t s = send(client_fd, buf + sent, r - sent, 0);
            if (s == -1) {
                if (errno == EINTR) continue;
                close(fd);
                pthread_mutex_unlock(&file_mutex);
                return -1;
            }
            sent += s;
        }
    }
    close(fd);
    pthread_mutex_unlock(&file_mutex);
    return 0;
}

void *client_thread(void *arg) {
    int client_fd = *(int *)arg;
    free(arg);

    char buf[BUFSIZE];
    char *packet_buf = NULL;
    size_t packet_size = 0;

    while (!exit_flag) {
        ssize_t r = recv(client_fd, buf, sizeof(buf), 0);
        if (r == -1) {
            if (errno == EINTR) continue;
            syslog(LOG_ERR, "recv: %s", strerror(errno));
            break;
        }
        if (r == 0) break;

        char *tmp = realloc(packet_buf, packet_size + r);
        if (!tmp) {
            syslog(LOG_ERR, "realloc failed");
            break;
        }
        packet_buf = tmp;
        memcpy(packet_buf + packet_size, buf, r);
        packet_size += r;

        char *newline;
        while ((newline = memchr(packet_buf, '\n', packet_size)) != NULL) {
            size_t pkt_len = (newline - packet_buf) + 1;

            pthread_mutex_lock(&file_mutex);
            int fd = open(DATAFILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (fd != -1) {
                write(fd, packet_buf, pkt_len);
                close(fd);
            } else {
                syslog(LOG_ERR, "file write failed: %s", strerror(errno));
            }
            pthread_mutex_unlock(&file_mutex);

            send_file(client_fd);

            size_t remaining = packet_size - pkt_len;
            memmove(packet_buf, packet_buf + pkt_len, remaining);
            packet_size = remaining;
            packet_buf = realloc(packet_buf, packet_size);
        }
    }

    free(packet_buf);
    close(client_fd);
    syslog(LOG_INFO, "Closed connection");
    return NULL;
}

void add_thread(pthread_t tid, int client_fd) {
    thread_node_t *node = malloc(sizeof(thread_node_t));
    if (!node) return;
    node->thread_id = tid;
    node->client_fd = client_fd;
    node->next = thread_list_head;
    thread_list_head = node;
}

void cleanup_threads()
{
    pthread_mutex_lock(&thread_list_mutex);
    thread_node_t *curr = thread_list_head;
    thread_node_t *prev = NULL;

    while (curr) {
        int res = pthread_join(curr->thread_id, NULL);
        if (res == 0) {
            if (prev) {
                prev->next = curr->next;
            } else {
                thread_list_head = curr->next;
            }
            thread_node_t *temp = curr;
            curr = curr->next;
            free(temp);
        } else {
            prev = curr;
            curr = curr->next;
        }
    }

    pthread_mutex_unlock(&thread_list_mutex);
}

int main(int argc, char *argv[]) {
    openlog("aesdsocket", LOG_PID, LOG_USER);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct addrinfo hints, *servinfo;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int status = getaddrinfo(NULL, PORT, &hints, &servinfo);
    if (status != 0) {
        syslog(LOG_ERR, "getaddrinfo: %s", gai_strerror(status));
        return -1;
    }

    listen_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if (listen_fd == -1) {
        syslog(LOG_ERR, "socket: %s", strerror(errno));
        freeaddrinfo(servinfo);
        return -1;
    }

    int yes = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    if (bind(listen_fd, servinfo->ai_addr, servinfo->ai_addrlen) == -1) {
        syslog(LOG_ERR, "bind: %s", strerror(errno));
        close(listen_fd);
        freeaddrinfo(servinfo);
        return -1;
    }

    freeaddrinfo(servinfo);

    if (listen(listen_fd, BACKLOG) == -1) {
        syslog(LOG_ERR, "listen: %s", strerror(errno));
        close(listen_fd);
        return -1;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            if (daemon(0, 0) == -1) {
                syslog(LOG_ERR, "daemon: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }
        }
    }

    pthread_t ts_tid;
    pthread_create(&ts_tid, NULL, timestamp_thread, NULL);

    while (!exit_flag) {
        struct sockaddr_storage their_addr;
        socklen_t addr_size = sizeof(their_addr);
        int *client_fd = malloc(sizeof(int));
        if (!client_fd) continue;

        *client_fd = accept(listen_fd, (struct sockaddr *)&their_addr, &addr_size);
        if (*client_fd == -1) {
            free(client_fd);
            if (errno == EINTR && exit_flag)
                break;
            if (errno == EINTR)
                continue;
            syslog(LOG_ERR, "accept: %s", strerror(errno));
            continue;
        }

        pthread_t tid;
        if (pthread_create(&tid, NULL, client_thread, client_fd) != 0) {
            syslog(LOG_ERR, "pthread_create failed");
            close(*client_fd);
            free(client_fd);
            continue;
        }

        pthread_mutex_lock(&thread_list_mutex);
        add_thread(tid, *client_fd);
        pthread_mutex_unlock(&thread_list_mutex);

        cleanup_threads();
    }

    pthread_cancel(ts_tid);
    pthread_join(ts_tid, NULL);

    pthread_mutex_lock(&thread_list_mutex);
    thread_node_t *curr = thread_list_head;
    while (curr) {
        pthread_join(curr->thread_id, NULL);
        thread_node_t *temp = curr;
        curr = curr->next;
        free(temp);
    }
    pthread_mutex_unlock(&thread_list_mutex);

    if (listen_fd != -1) close(listen_fd);
    unlink(DATAFILE);
    closelog();
    return 0;
}

