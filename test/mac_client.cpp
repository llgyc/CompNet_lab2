#include <iostream>
#include "../inc/device.h"
#include "../inc/packetio.h"

using namespace tinytcp;

int main(int argc, char **argv) {

    if (argc != 2) {
        fprintf(stderr, "Usage: test1 <device_name>\n");
        return 0;
    }
    if (device::addDevice(argv[1]) == -1) {
        fprintf(stderr, "ERROR: not a valid device\n");
        return 0;
    }
    int id = device::findDevice(argv[1]);
    printf("Added device: %s  ID: %d\n", argv[1], id);
    
    const int N = 100;
    char *buf = new char[N]; buf[0] = 0x45;
    for (int i= 1; i < N; i++) buf[i] = i;

    eth::addr_t mac = {0x0a, 0xde, 0x39, 0x7d, 0x20, 0x0a};
    // 0x0800 IPv4
    eth::sendFrame(buf, N, 0x0800, (void *)mac, id);
    

    return 0;
}
