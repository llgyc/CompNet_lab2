#include <iostream>
#include "../inc/device.h"
#include "../inc/packetio.h"

using namespace tinytcp;

int echo_callback(const void *buf, int len, int id) {
    const uint8_t *ptr = (const uint8_t *)buf;
    printf("============================\n");
    printf("Received frame:\n");
    for (int i = 0; i < len; i++)
        printf("%02x%c", ptr[i], " \n"[i % 8 == 7]);
    putchar('\n');
    printf("============================\n");
    return 0;
}

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
    
    eth::setFrameReceiveCallback(echo_callback);
    
    eth::startCapture(id);
    
    printf("Capture ended.\n");

    return 0;
}
