#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <random>
#include <stdint.h>
#include <unistd.h>
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

void printPort(tcp::PortType port) {
    fprintf(stderr, "%u", endian_reverse(port));
}

uint16_t calcChecksum(uint8_t *buf, int len) {
    uint32_t sum = 0;
    if (len & 1) {
        sum = buf[len-1] << 8;
        len--;
    }
    len /= 2;
    uint16_t *buf2 = (uint16_t *)buf;
    for (int i = 0; i < len ; i++) {
        sum += endian_reverse(buf2[i]);
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    uint16_t ret = sum; ret = ~ret;
    return endian_reverse(ret);
}

int allocate_new_fd() {
    static int null_fd = open("/dev/null", 0, 0);
    return dup(null_fd);
}

/* Reference: https://stackoverflow.com/questions/7961029/how-can-i-kill-a-pthread-that-is-in-an-infinite-loop-from-outside-that-loop */
int needQuit(pthread_mutex_t *mtx)
{
    switch(pthread_mutex_trylock(mtx)) {
        case 0: /* if we got the lock, unlock and return 1 (true) */
            pthread_mutex_unlock(mtx);
            return 1;
        case EBUSY: /* return 0 (false) if the mutex was locked */
            return 0;
    }
    return 1;
}

uint32_t rand32bit() {
    static std::random_device rseed;
    static std::mt19937 rgen(rseed()); // mersenne_twister
    static std::uniform_int_distribution<uint32_t> idist(0,(uint32_t)-1);
    return idist(rgen);
}

int initAll(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <device_name> [...]\n", argv[0]);
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
    tcp::init();
    return 0;
}

}
}
