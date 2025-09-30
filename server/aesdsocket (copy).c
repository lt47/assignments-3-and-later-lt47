#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
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

#define PORT "9000"
#define BACKLOG 10
#define DATAFILE "/var/tmp/aesdsocketdata"
#define BUFSIZE 1024

static volatile sig_atomic_t exit_flag = 0;
static int listen_fd = -1;

void handle_signal(int signal) {
    syslog(LOG_INFO, "Caught signal, exiting");
    exit_flag = 1;
    if (signal == SIGINT || signal == SIGCHLD || signal == SIGTERM) {
        close(listen_fd);
        listen_fd = -1;
    }
}

int append_packet(const char *buf, size_t len) {
    int fd = open(DATAFILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd == -1) {
        syslog(LOG_ERR, "open: %s", strerror(errno));
        return -1;
    }
    ssize_t w = write(fd, buf, len);
    if (w != (ssize_t)len) {
        syslog(LOG_ERR, "write: %s", strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int send_file(int client_fd) {
    int fd = open(DATAFILE, O_RDONLY);
    if (fd == -1) {
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
                return -1;
            }
            sent += s;
        }
    }
    close(fd);
    return 0;
}

int main(void) {
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

    while (!exit_flag) {
        struct sockaddr_storage their_addr;
        socklen_t addr_size = sizeof their_addr;
        int client_fd = accept(listen_fd, (struct sockaddr *)&their_addr, &addr_size);
        if (client_fd == -1) {
            if (errno == EINTR) continue; 
            syslog(LOG_ERR, "accept: %s", strerror(errno));
            continue;
        }

        char ipstr[INET6_ADDRSTRLEN];
        void *addr;
        if (their_addr.ss_family == AF_INET) {
            addr = &((struct sockaddr_in *)&their_addr)->sin_addr;
        } else {
            addr = &((struct sockaddr_in6 *)&their_addr)->sin6_addr;
        }
        inet_ntop(their_addr.ss_family, addr, ipstr, sizeof ipstr);
        syslog(LOG_INFO, "Accepted connection from %s", ipstr);

        // Accumulate buffer
        char *buffer = NULL;
        size_t buf_len = 0;

        while (!exit_flag) {
            char temp[BUFSIZE];
            ssize_t r = recv(client_fd, temp, sizeof temp, 0);
            if (r == -1) {
                if (errno == EINTR) continue;
                syslog(LOG_ERR, "recv: %s", strerror(errno));
                break;
            }
            if (r == 0) break; 

            char *tmp = realloc(buffer, buf_len + r + 1);
            if (!tmp) {
                syslog(LOG_ERR, "realloc failed");
                free(buffer);
                buffer = NULL;
                buf_len = 0;
                continue;
            }
            buffer = tmp;
            memcpy(buffer + buf_len, temp, r);
            buf_len += r;
            buffer[buf_len] = '\0';

            char *newline;
            while ((newline = memchr(buffer, '\n', buf_len)) != NULL) {
                size_t pkt_len = (newline - buffer) + 1;
                append_packet(buffer, pkt_len);
                send_file(client_fd);

                // shift buffer
                size_t remaining = buf_len - pkt_len;
                memmove(buffer, buffer + pkt_len, remaining);
                buf_len = remaining;
                buffer = realloc(buffer, buf_len + 1);
                if (buffer) buffer[buf_len] = '\0';
            }
        }

        free(buffer);
        close(client_fd);
        syslog(LOG_INFO, "Closed connection from %s", ipstr);
    }

    if (listen_fd != -1) close(listen_fd);
    unlink(DATAFILE);
    closelog();
    return 0;
}

