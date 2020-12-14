#include <iostream>
#include <string.h>
#include "../inc/tinytcp.h"

using namespace tinytcp;

int main(int argc, char **argv) {

    helper::initAll(argc, argv);
    int clientfd = -1;
    struct addrinfo hints, *listp, *p;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    hints.ai_flags |= AI_ADDRCONFIG;
    getaddrinfo("10.100.2.2", "8080", &hints, &listp);
    for (p = listp; p; p = p->ai_next) {
        if ((clientfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
            continue;
        if (connect(clientfd, p->ai_addr, p->ai_addrlen) != -1)
            break;
        close(clientfd);
    }
    freeaddrinfo(listp);
    if (!p) {
        fprintf(stderr, "[ERROR] connect() failed\n");
        return 0;
    }
    char buf[200], buf2[200];
    for (int i = 0; i < 100; i++) buf[i] = i;
    int num = write(clientfd, buf, 100);
    printf("[INFO] Successfully sent %d bytes\n", num);
    num = write(clientfd, buf, 100);
    printf("[INFO] Successfully sent %d bytes\n", num);
    int num2 = read(clientfd, buf2, 200);
    for (int i = 0; i < num2; i++) {
        printf("%02x ", (uint8_t)buf2[i]);
        if (i % 16 == 15) puts("");
    } puts("");
    printf("[INFO] Successfully received %d bytes\n", num2);
    close(clientfd);
    printf("[INFO] Closing ... Press Ctrl + C to shutdown\n");
    while (1);

    return 0;
}
