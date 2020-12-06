#include <iostream>
#include "../inc/device.h"
#include "../inc/packetio.h"

using namespace tinytcp;

int main(int argc, char **argv) {

    if (argc != 2) {
        fprintf(stderr, "Usage: print_my_ip <device_name>\n");
        return 0;
    }
    if (device::addDevice(argv[1]) == -1) {
        fprintf(stderr, "ERROR: not a valid device\n");
        return 0;
    }
    int id = device::findDevice(argv[1]);
    printf("Added device: %s  ID: %d\n", argv[1], id);
    
    const device::Device *dev = device::getDevice(id);
    printf("IP address: ");
    uint8_t *ptr = (uint8_t *)&dev->ip;
    for (int i = 0; i < 4; i++) {
        if (i) putchar(':');
        printf("%d", *(ptr + i));
    }
    putchar('\n');

    return 0;
}
