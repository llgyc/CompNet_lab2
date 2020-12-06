#include <stdint.h>
#include <algorithm>
#include <sys/time.h>

#include "../inc/helper.h"

namespace tinytcp {
namespace helper {
    
uint16_t endian_reverse(uint16_t num) {
    uint8_t *ptr = (uint8_t *)&num;
    std::swap(ptr[0], ptr[1]);
    return num;
}
uint32_t endian_reverse(uint32_t num) {
    uint8_t *ptr = (uint8_t *)&num;
    std::swap(ptr[0], ptr[3]);
    std::swap(ptr[1], ptr[2]);
    return num;
}

time_t getTime() {
    timeval now;
    gettimeofday(&now, NULL);
    return now.tv_sec;
}

void printIP(ip::addr_t ip) {
    uint8_t *ptr = (uint8_t *)&ip;
    for (int i = 0; i < 4; i++) {
        if (i) fprintf(stderr, ".");
        fprintf(stderr, "%3d", *(ptr + i));
    }
}

void printMAC(eth::addr_t mac) {
    for (int i = 0; i < 6; i++) {
        if (i) fprintf(stderr, ":");
        fprintf(stderr, "%02x", mac[i]);
    }
}

}
}
