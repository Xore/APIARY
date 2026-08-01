/* Opens a TCP socket to a hardcoded loopback address and port -- a
 * behavior-shaped fixture (network access) that is non-routable and safe:
 * it never leaves the local host and the address is fixed, not
 * attacker-controlled. Category: network access. */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
int connect_local_status_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(19999);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc != 0) {
        close(fd);
        return -1;
    }
    return fd;
}
