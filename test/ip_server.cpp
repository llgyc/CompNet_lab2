#include <string.h>
#include <iostream>


#include "../inc/device.h"
#include "../inc/helper.h"
#include "../inc/packetio.h"

using namespace tinytcp;

void contentCallback(ip::addr_t ip1, ip::addr_t ip2, const void* buf, int len) {
    ip::header *hd = (ip::header *) buf;
    if (ip::isBroadcast(hd -> dstAddr)) return;
    struct in_addr src, dest;
    memcpy(&src, &hd -> dstAddr, sizeof(ip::addr_t));
    memcpy(&dest, &hd -> srcAddr, sizeof(ip::addr_t));
    //int proto = 0xfd; // 253 experiment protocol
    int proto = hd -> protocol;
    uint8_t hdlen = (hd -> ver_IHL & 0xf) << 2;
    ip::sendIPPacket(src, dest, proto, (char *)buf + hdlen, helper::endian_reverse(hd -> totLen) - hdlen);
    return;
}

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
    
    ip::setIPContentCallback(contentCallback);
    ip::setup();
    
    while (1) {};
    
    ip::cleanup();

    return 0;
}
