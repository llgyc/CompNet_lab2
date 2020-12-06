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
    
    while (1) {};
    
    ip::cleanup();

    return 0;
}
