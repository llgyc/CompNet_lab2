#include <iostream>
#include <string.h>
#include "../inc/tinytcp.h"

using namespace tinytcp;

void echo(int fd) {
    int n;
    char buf[200];
    while ((n = read(fd, buf, 200)) > 0) {
        fprintf(stderr, "[INFO] Server received %d bytes\n", n);
        int n2 = write(fd, buf, n);
        fprintf(stderr, "[INFO] Server echoed %d bytes\n", n2);
    }
}

int main(int argc, char **argv) {

    helper::initAll(argc, argv);
    int listenfd = -1, connfd;
    struct addrinfo hints, *listp, *p;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
    hints.ai_flags |= AI_ADDRCONFIG;
    getaddrinfo(NULL, "8080", &hints, &listp);
    for (p = listp; p; p = p->ai_next) {
        if ((listenfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
            continue;
        if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0)
            break;
        close(listenfd);
    }
    freeaddrinfo(listp);
    if (!p) {
        fprintf(stderr, "[ERROR] bind() failed\n");
        return 0;
    }
    if (listen(listenfd, 1024) < 0) {
        close(listenfd);
        fprintf(stderr, "[ERROR] bind() failed\n");
        return 0;
    }
    socklen_t clientlen;
    struct sockaddr_in clientaddr;
    while (1) {
        clientlen = sizeof(struct sockaddr_in);
        connfd = accept(listenfd, (struct sockaddr *)&clientaddr, &clientlen);
        fprintf(stderr, "[INFO] Connected to client ");
        helper::printIP(clientaddr.sin_addr.s_addr); puts("");
        echo(connfd);
        close(connfd);
        fprintf(stderr, "[INFO] Connection closed\n");
    }

    return 0;
}
