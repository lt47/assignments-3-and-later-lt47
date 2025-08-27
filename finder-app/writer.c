#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    openlog("writer", LOG_PID, LOG_USER);

    if (argc != 3) {
        syslog(LOG_ERR, "Error: Expected 2 arguments, got %d", argc - 1);
        fprintf(stderr, "Usage: %s <writefile> <writestr>\n", argv[0]);
        closelog();
        exit(1);
    }

    const char *writefile = argv[1];
    const char *writestr  = argv[2];

    
    syslog(LOG_DEBUG, "Writing \"%s\" to %s", writestr, writefile);

    
    int fd = creat(writefile, 0666);
    if (fd == -1) {
        syslog(LOG_ERR, "Error: Could not create file %s (errno=%d)", writefile, errno);
        perror("creat");
        closelog();
        exit(1);
    }

    ssize_t len = strlen(writestr);
    ssize_t written = write(fd, writestr, len);
    if (written == -1 || written != len) {
        syslog(LOG_ERR, "Error: Failed to write to file %s (errno=%d)", writefile, errno);
        perror("write");
        close(fd);
        closelog();
        exit(1);
    }

    close(fd);
    closelog();
    return 0;
}
