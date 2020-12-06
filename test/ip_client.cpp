#include <unistd.h>
#include <iostream>
#include "../inc/device.h"
#include "../inc/packetio.h"

using namespace tinytcp;

int main(int argc, char **argv) {

    if (argc < 2) {
        fprintf(stderr, "Usage: test1 <device_name> [...]\n");
        return 0;
    }
    
    ip::epollInit();

    for (int i = 1; i < argc; i++) {
        if (device::addDevice(argv[i]) == -1) {
            fprintf(stderr, "ERROR: %s is not a valid device\n", argv[i]);
            return 0;
        }
    }
    
    ip::setup();
    sleep(25);
    
    struct in_addr src, dest;
    src.s_addr = 0x0101640a;
    dest.s_addr = 0x0202640a;
    
    int proto = 0xfd;
    char buf[50];
    int len = 50;
    for (int i = 0; i < len; i++) buf[i] = 0xaa + i;
    ip::sendIPPacket(src, dest, proto, buf, len);
    
    while (1) {};
    
    ip::cleanup();

    return 0;
}
