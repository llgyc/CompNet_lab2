#include <set>
#include <cstring>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../inc/ip.h"
#include "../inc/route.h"
#include "../inc/device.h"
#include "../inc/helper.h"

namespace tinytcp {
namespace ip {

pthread_mutex_t ident_mutex;
static volatile uint16_t ident = rand();

static std::set<ip::addr_t> all_ips;

bool isMyIP(ip::addr_t ip) {
    if (all_ips.find(ip) != all_ips.end())
        return true;
    return false;
}

/* Reference: https://www.cnblogs.com/dapaitou2006/p/6502195.html */
int getIPAddr(const char *device, ip::addr_t *ip) {
    int fd = socket(AF_PACKET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    size_t if_name_len = strlen(device);
    
    if (fd == -1) {
        fprintf(stderr, "ERROR: getIPAddr() - socket() failed\n");
        return -1;
    }
    
    if(if_name_len < sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name, device, if_name_len);
        ifr.ifr_name[if_name_len] = '\0';
    } else {
        fprintf(stderr, "ERROR: getIPAddr() - interface name is too long\n");
        close(fd);
        return -1;
    }
    
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        fprintf(stderr, "ERROR: getIPAddr() - %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    
    memcpy(ip, &ipaddr->sin_addr, sizeof(ip::addr_t));
    all_ips.insert(*ip);
    
    close(fd);
    return 0;
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
        sum += helper::endian_reverse(buf2[i]);
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    uint16_t ret = sum; ret = ~ret;
    return helper::endian_reverse(ret);
}
    
int sendIPPacket(const struct in_addr src, const struct in_addr dest, 
    int proto, const void *buf, int len) {
    uint8_t *packet = new uint8_t[sizeof(ip::header) + len];
    ip::header *hd = (ip::header *) packet;
    hd -> ver_IHL = 0x45;
    hd -> TOS = 0;
    uint16_t totLen = sizeof(ip::header) + len;
    hd -> totLen = helper::endian_reverse(totLen);
    hd -> ident = ident;
    ident++;
    hd -> frag = 0x0040u;
    hd -> TTL = 32;
    hd -> protocol = proto;
    hd -> checksum = 0;
    hd -> srcAddr = src.s_addr;
    hd -> dstAddr = dest.s_addr;
    memcpy(packet + sizeof(ip::header), buf, len);
    hd -> checksum = calcChecksum(packet, sizeof(ip::header));
    route::packetIdent ide;
    ide.srcAddr = hd -> srcAddr;
    ide.ident = hd -> ident;
    packetAdd(ide);
        
    route::entryValue val = route::tableLookup(dest.s_addr);
    if (ip::isBroadcast(*(ip::addr_t *)&dest) || val.id == -1) {
        int id = 0, ret = 0;
        while (true) {
            const device::Device *dev = device::getDevice(id); 
            if (dev == NULL) break;
            ret |= eth::sendFrame(packet, sizeof(ip::header) + len, 0x0800u, eth::BROADCAST, id);
            id++;
        }
        delete [] packet;
        if (ret == 0 && id == 0) {
            fprintf(stderr, "ERROR: sendIPPacket() failed"
                    " - default device does not exist\n");
            return -1;
        }
        return ret;
    }
    
    int ret = eth::sendFrame(packet, sizeof(ip::header) + len, 0x0800u, val.nextHopMAC, val.id);
    delete [] packet;
    return ret;
    
}

void decreaseTTL(const void *packet) {
    ip::header *hd = (ip::header *)packet;
    hd -> TTL--;
    hd -> checksum = 0;
    hd -> checksum = calcChecksum((uint8_t *)packet, sizeof(ip::header));
}

int defaultIPContentCallback(const void* buf, int len) {
    const uint8_t *ptr = (const uint8_t *)buf;
    fprintf(stderr, "===== Received packet =====\n");
    for (int i = 0; i < len; i++)
        fprintf(stderr, "%02x%c", ptr[i], " \n"[i % 8 == 7]);
    fprintf(stderr, "\n===========================\n");
    return 0;
}

static IPPacketReceiveCallback content_callback = defaultIPContentCallback;

int defaultIPCallback(const void* buf, int len) {
    ip::header *hd = (ip::header *)buf;
    /* TTL timeout */
    if (hd -> TTL == 0)
        return 0;
        
    /* Protect from flooding */
    route::packetIdent ide;
    ide.srcAddr = hd -> srcAddr;
    ide.ident = hd -> ident;
    if (packetExist(ide)) return 0;
      
    /* Add to packet history */
    packetAdd(ide);
            
    int ret = 0;
    /* Forwarding a packet */
    if (!isMyIP(hd -> dstAddr)) {
        uint8_t *packet = new uint8_t[len];
        memcpy(packet, buf, len);
        decreaseTTL(packet);
        
        route::entryValue val = route::tableLookup(hd -> dstAddr);    
        if (ip::isBroadcast(hd -> dstAddr) || val.id == -1) {
            int id = 0;
            while (true) {
                const device::Device *dev = device::getDevice(id); 
                if (dev == NULL) break;
                ret |= eth::sendFrame(packet, len, 0x0800u, eth::BROADCAST, id);
                id++;
            }
            
            delete [] packet;
            if (ret == 0 && id == 0) {
                fprintf(stderr, "ERROR: defaultIPCallback() failed"
                        " - default device does not exist\n");
                ret |= -1;
            }
        } else {
            ret = eth::sendFrame(packet, len, 0x0800u, val.nextHopMAC, val.id);
            delete [] packet;
        }
    }
    
    /* Handling incoming packets */
    if (isMyIP(hd->dstAddr) || ip::isBroadcast(hd -> dstAddr)) {    
        content_callback(buf, len);
    }
    
    return ret;
}

static IPPacketReceiveCallback callback = nullptr;

int callback4eth (const void *buf, int len, int id) {
    eth::addr_t destmac, srcmac;
    memcpy(&destmac, buf, sizeof(eth::addr_t));
    memcpy(&srcmac, (char *)buf + 6, sizeof(eth::addr_t));
    uint16_t ethtype = helper::endian_reverse(*(uint16_t *)((char *)buf + 12));
    if (!(eth::isBroadcast(destmac) || 
        eth::equalAddr(destmac, device::getDevice(id) -> mac))) {
        return 0;        
    }
    if (ethtype == 0x0800u) {
        /* Update Routing Table */
        ip::header *hd = (ip::header *)((char *)buf + 14);
        struct in_addr dest, mask;
        memcpy(&dest, &hd -> srcAddr, sizeof(ip::addr_t));
        memcpy(&mask, &ip::BROADCAST, sizeof(ip::addr_t));
        const device::Device *dev = device::getDevice(id);
        /* Protect from flooding */
        route::packetIdent ide;
        ide.srcAddr = hd -> srcAddr;
        ide.ident = hd -> ident;
        if (!packetExist(ide))
            setRoutingTable(dest, mask, srcmac, dev -> name.c_str());
        return callback((char *)buf + 14, len - 14);
    }
    else 
        return 0;
};

int setIPPacketReceiveCallback(IPPacketReceiveCallback callback) {
    ip::callback = callback;
    eth::setFrameReceiveCallback(callback4eth);
    return 0;
}

int setIPContentCallback(IPPacketReceiveCallback callback) {
    content_callback = callback;
    return 0;
}

int setRoutingTable(const struct in_addr dest, const struct in_addr mask, 
    const void* nextHopMAC, const char *device) {
    route::entryKey key;
    memcpy(&key.dstAddr, &dest, sizeof(ip::addr_t));
    memcpy(&key.mask, &mask, sizeof(ip::addr_t));
    route::entryValue value;
    memcpy(&value.nextHopMAC, nextHopMAC, sizeof(eth::addr_t));
    value.id = device::findDevice(device);
    route::tableUpdate(key, value);
    return 0;
}

bool isBroadcast(ip::addr_t ip) {
    return (ip == ip::BROADCAST);
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

static pthread_t reader;
static pthread_t alarm;
static pthread_mutex_t reader_thread_mutex;
static pthread_mutex_t alarm_thread_mutex;

const int MAXEVENTS = 256;
static int epfd;
struct epoll_event events[MAXEVENTS];

void *reader_thread(void *arg) {
    pthread_mutex_t *mtx = (pthread_mutex_t *)arg;
    while (!needQuit(mtx)) {
        int nfds = epoll_wait(epfd, events, MAXEVENTS, 1);
        if (nfds < 0) {
            fprintf(stderr, "ERROR: reader_thread() failed\n");
            return NULL;
        }
        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            if (events[i].events & EPOLLERR) {
               fprintf(stderr, "ERROR: epoll events failed - %s\n", strerror(errno));
               continue;
            }
            eth::startCapture(device::getIdFromFd(fd));
        }
    }
    return NULL;
}

void *alarm_thread(void *arg) {
    pthread_mutex_t *mtx = (pthread_mutex_t *)arg;
    while (!needQuit(mtx)) {
        for (auto ip: all_ips) {
            struct in_addr src, dest;
            memcpy(&src, &ip, sizeof(ip::addr_t));
            memcpy(&dest, &ip::BROADCAST, sizeof(ip::addr_t));
            int proto = 0xfd; // 253 experiment protocol
            char buf;
            sendIPPacket(src, dest, proto, &buf, 0);
        }
        route::packetForget();
        route::tableForget();
        fprintf(stderr, "Ring!\n");
        sleep(10);
    }
    return NULL;
}

int epollInit() {        
    epfd = epoll_create(1);
    if (epfd == -1) {
        fprintf(stderr, "ERROR: ip::setup() - %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

int setup() {
    pthread_mutex_init(&reader_thread_mutex, NULL);
    pthread_mutex_init(&alarm_thread_mutex, NULL);
    pthread_mutex_lock(&reader_thread_mutex);
    pthread_mutex_lock(&alarm_thread_mutex);
    
    pthread_mutex_init(&ident_mutex, NULL);
    
    eth::mutexinit();
    route::mutexinit();

    srand(time(NULL));
    setIPPacketReceiveCallback(defaultIPCallback);
    
    pthread_create(&reader, NULL, reader_thread, &reader_thread_mutex);
    pthread_create(&alarm, NULL, alarm_thread, &alarm_thread_mutex);
    
    return 0;
    
}

int cleanup() {

    pthread_mutex_unlock(&reader_thread_mutex);
    pthread_mutex_unlock(&alarm_thread_mutex);
    pthread_mutex_destroy(&reader_thread_mutex);
    pthread_mutex_destroy(&alarm_thread_mutex);
    pthread_mutex_destroy(&ident_mutex);
    
    pthread_join(reader, NULL);
    pthread_join(alarm, NULL);
    
    return 0;
}

int register_epoll(int fd) {
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLERR;
 	ev.data.fd = fd;
 	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        fprintf(stderr, "ERROR: register_epoll() %d failed\n", fd);
        return -1;
    }
    return 0;
}

}
}
