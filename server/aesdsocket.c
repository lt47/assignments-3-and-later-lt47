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
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

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

thread_node_t *thread_list_head = NULL;
pthread_mutex_t thread_list_mutex = PTHREAD_MUTEX_INITIALIZER;

void handle_signal(int signal) {
    syslog(LOG_INFO, "Caught signal, exiting");
    exit_flag = 1;
    if (listen_fd != -1) close(listen_fd);
}

int append_packet(const char *buf, size_t len) {
    int ret = 0;
    pthread_mutex_lock(&file_mutex);
    int fd = open(DATAFILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd == -1) {
        syslog(LOG_ERR, "open: %s", strerror(errno));
        pthread_mutex_unlock(&file_mutex);
        return -1;
    }
    ssize_t w = write(fd, buf, len);
    if (w != (ssize_t)len) {
        syslog(LOG_ERR, "write: %s", strerror(errno));
        ret = -1;
    }
    close(fd);
    pthread_mutex_unlock(&file_mutex);
    return ret;
}

int send_file(int client_fd) {
    pthread_mutex_lock(&file_mutex);
    int fd = open(DATAFILE, O_RDONLY);
    if (fd == -1) {
        pthread_mutex_unlock(&file_mutex);
        if (errno != ENOENT)
            syslog(LOG_ERR, "open (read): %s", strerror(errno));
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
                syslog(LOG_ERR, "send: %s", strerror(errno));
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
    char buffer[BUFSIZE];
    char *packet_buf = NULL;
    size_t packet_len = 0;
    while (!exit_flag) {
        ssize_t r = recv(client_fd, buffer, sizeof(buffer), 0);
        if (r == -1) {
            if (errno == EINTR) continue;
            syslog(LOG_ERR, "recv: %s", strerror(errno));
            break;
        }
        if (r == 0) break;
        char *tmp = realloc(packet_buf, packet_len + r + 1);
        if (!tmp) {
            syslog(LOG_ERR, "realloc failed");
            free(packet_buf);
            packet_buf = NULL;
            packet_len = 0;
            continue;
        }
        packet_buf = tmp;
        memcpy(packet_buf + packet_len, buffer, r);
        packet_len += r;
        packet_buf[packet_len] = '\0';
        char *newline;
        while ((newline = memchr(packet_buf, '\n', packet_len)) != NULL) {
            size_t pkt_len = (newline - packet_buf) + 1;
            append_packet(packet_buf, pkt_len);
            send_file(client_fd);
            size_t remaining = packet_len - pkt_len;
            memmove(packet_buf, packet_buf + pkt_len, remaining);
            packet_len = remaining;
            packet_buf = realloc(packet_buf, packet_len + 1);
            if (packet_buf) packet_buf[packet_len] = '\0';
        }
    }
    free(packet_buf);
    close(client_fd);
    syslog(LOG_INFO, "Closed client connection");
    return NULL;
}

void add_thread(pthread_t tid, int client_fd) {
    thread_node_t *node = malloc(sizeof(thread_node_t));
    node->thread_id = tid;
    node->client_fd = client_fd;
    node->next = NULL;
    pthread_mutex_lock(&thread_list_mutex);
    node->next = thread_list_head;
    thread_list_head = node;
    pthread_mutex_unlock(&thread_list_mutex);
}

void cleanup_threads() {
    pthread_mutex_lock(&thread_list_mutex);
    thread_node_t *curr = thread_list_head;
    while (curr) {
        pthread_join(curr->thread_id, NULL);
        thread_node_t *temp = curr;
        curr = curr->next;
        free(temp);
    }
    thread_list_head = NULL;
    pthread_mutex_unlock(&thread_list_mutex);
}

void *timestamp_thread(void *arg) {
    (void)arg;
    while (!exit_flag) {
        sleep(10);
        if (exit_flag) break;
        time_t t = time(NULL);
        struct tm *tm_info = localtime(&t);
        char time_str[128];
        strftime(time_str, sizeof(time_str), "%a, %d %b %Y %H:%M:%S %z", tm_info);
        char entry[256];
        snprintf(entry, sizeof(entry), "timestamp:%s\n", time_str);
        append_packet(entry, strlen(entry));
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    openlog("aesdsocket", LOG_PID, LOG_USER);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
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
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
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
    if (argc == 2 && strcmp(argv[1], "-d") == 0) {
        if (daemon(0, 0) == -1) {
            syslog(LOG_ERR, "daemon failed: %s", strerror(errno));
            return -1;
        }
    }
    syslog(LOG_INFO, "Server started on port %s", PORT);
    pthread_t ts_thread;
    if (pthread_create(&ts_thread, NULL, timestamp_thread, NULL) != 0) {
        syslog(LOG_ERR, "pthread_create timestamp failed");
        return -1;
    }
    while (!exit_flag) {
        struct sockaddr_storage their_addr;
        socklen_t addr_size = sizeof their_addr;
        int *client_fd = malloc(sizeof(int));
        *client_fd = accept(listen_fd, (struct sockaddr *)&their_addr, &addr_size);
        if (*client_fd == -1) {
            free(client_fd);
            if (errno == EINTR && exit_flag) break;
            syslog(LOG_ERR, "accept: %s", strerror(errno));
            continue;
        }
        char ipstr[INET6_ADDRSTRLEN];
        void *addr;
        if (their_addr.ss_family == AF_INET)
            addr = &((struct sockaddr_in *)&their_addr)->sin_addr;
        else
            addr = &((struct sockaddr_in6 *)&their_addr)->sin6_addr;
        inet_ntop(their_addr.ss_family, addr, ipstr, sizeof ipstr);
        syslog(LOG_INFO, "Accepted connection from %s", ipstr);
        pthread_t tid;
        if (pthread_create(&tid, NULL, client_thread, client_fd) != 0) {
            syslog(LOG_ERR, "pthread_create failed");
            close(*client_fd);
            free(client_fd);
            continue;
        }
        add_thread(tid, *client_fd);
    }
    syslog(LOG_INFO, "Shutting down server");
    cleanup_threads();
    pthread_join(ts_thread, NULL);
    unlink(DATAFILE);
    closelog();
    return 0;
}
