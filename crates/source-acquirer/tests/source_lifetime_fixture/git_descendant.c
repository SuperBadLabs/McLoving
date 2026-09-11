/* Trusted fixture Git wrapper, never a production launch program selector.
 * The configured, digest-pinned binary executes real Git and deliberately
 * creates a new-session descendant during fetch. Its synthetic read heartbeat
 * is counted independently from real authenticated Git upload-pack traffic.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "git_descendant_config.h"

static void heartbeat(void) {
    if (setsid() < 0 || prctl(PR_SET_NAME, "src-fixture-pg", 0, 0, 0) < 0) _exit(71);
    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd < 0) _exit(72);
    for (int fd = 0; fd < 3; fd++) if (dup2(null_fd, fd) < 0) _exit(73);
    if (null_fd > 2) close(null_fd);
    signal(SIGPIPE, SIG_IGN);
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 20000000};
    for (int iteration = 0; iteration < 6000; iteration++) {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) _exit(74);
        struct sockaddr_in endpoint = {.sin_family = AF_INET, .sin_port = htons(HEARTBEAT_PORT)};
        endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        struct timeval timeout = {.tv_sec = 1};
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        if (connect(fd, (struct sockaddr *)&endpoint, sizeof(endpoint)) == 0) {
            const char request[] = "GET /fixture-descendant-heartbeat HTTP/1.0\r\nHost: localhost\r\nAuthorization: " HEARTBEAT_AUTH "\r\n\r\n";
            if (write(fd, request, sizeof(request) - 1) == (ssize_t)(sizeof(request) - 1)) {
                char response[256];
                if (read(fd, response, sizeof(response)) < 0) { close(fd); _exit(78); }
            }
        }
        close(fd);
        nanosleep(&pause, NULL);
    }
    _exit(75);
}

int main(int argc, char **argv) {
    int fetch = 0;
    for (int i = 1; i < argc; i++) if (strcmp(argv[i], "fetch") == 0) fetch = 1;
    if (fetch) {
        pid_t child = fork();
        if (child < 0) return 76;
        if (child == 0) heartbeat();
    }
    argv[0] = REAL_GIT;
    execv(REAL_GIT, argv);
    return 77;
}
